package store

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
)

var (
	ErrCouponNotFound = errors.New("coupon not found or inactive")
	ErrCouponRedeemed = errors.New("coupon already redeemed by your organization")
)

// GetCouponByCode looks up an active coupon by its code (case-insensitive).
func (s *Store) GetCouponByCode(ctx context.Context, code string) (*model.Coupon, error) {
	var c model.Coupon
	err := s.pool.QueryRow(ctx, `
		SELECT id, code, plan_tier, description, is_active, created_at
		FROM coupons
		WHERE LOWER(code) = LOWER($1) AND is_active = true`,
		strings.TrimSpace(code)).
		Scan(&c.ID, &c.Code, &c.PlanTier, &c.Description, &c.IsActive, &c.CreatedAt)
	if err != nil {
		return nil, ErrCouponNotFound
	}
	return &c, nil
}

// RedeemCoupon applies the coupon to the organization in an atomic transaction.
func (s *Store) RedeemCoupon(ctx context.Context, coupon *model.Coupon, orgID, userID uuid.UUID, retentionDays int) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Check if already redeemed
	var exists bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM coupon_redemptions
			WHERE coupon_id = $1 AND org_id = $2
		)`, coupon.ID, orgID).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return ErrCouponRedeemed
	}

	// Record redemption
	_, err = tx.Exec(ctx, `
		INSERT INTO coupon_redemptions (coupon_id, org_id, user_id, redeemed_at)
		VALUES ($1, $2, $3, NOW())`,
		coupon.ID, orgID, userID)
	if err != nil {
		return err
	}

	// Update org plan tier
	_, err = tx.Exec(ctx, `
		UPDATE organizations
		SET plan_tier = $2,
		    audit_retention_days = $3,
		    subscription_status = 'active',
		    updated_at = NOW()
		WHERE id = $1`,
		orgID, coupon.PlanTier, retentionDays)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}
