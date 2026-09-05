package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/nan0/backend/internal/billing"
	"github.com/nan0/backend/internal/cache"
	"github.com/nan0/backend/internal/crypto"
	"github.com/nan0/backend/internal/email"
	"github.com/nan0/backend/internal/handler"
	"github.com/nan0/backend/internal/middleware"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/respond"
	"github.com/nan0/backend/internal/rotation"
	"github.com/nan0/backend/internal/store"
	"github.com/nan0/backend/internal/ws"
)

type Config struct {
	DB             *store.Store
	Cache          *cache.Cache
	JWTSecret      string
	SupabaseURL    string
	EncryptionKey  string
	AuditHMACKey   string
	AllowedOrigins string
	Email          *email.Client
	Hub            *ws.Hub
	Worker         *rotation.Worker
}

// requirePlan returns middleware that blocks the request if the org's plan is below minPlan.
func requirePlan(db *store.Store, minPlan model.PlanTier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			orgUUID, ok := middleware.GetOrgUUIDFromCtx(r)
			if !ok {
				respond.Error(w, http.StatusForbidden, "no organization")
				return
			}
			org, err := db.GetOrganizationByID(r.Context(), orgUUID)
			if err != nil || org == nil {
				respond.Error(w, http.StatusInternalServerError, "failed to verify plan")
				return
			}
			if !billing.IsAtLeastPlan(org.PlanTier, minPlan) {
				respond.Error(w, http.StatusPaymentRequired,
					"this feature requires the "+string(minPlan)+" plan or higher — upgrade at /billing")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func NewRouter(cfg Config) http.Handler {
	r := chi.NewRouter()

	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	sentryHandler := sentryhttp.New(sentryhttp.Options{Repanic: true})
	r.Use(sentryHandler.Handle)

	origins := strings.Split(cfg.AllowedOrigins, ",")
	if len(origins) == 0 || (len(origins) == 1 && origins[0] == "") {
		origins = []string{"http://localhost:3000"}
	}
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if hub := sentry.GetHubFromContext(req.Context()); hub != nil {
				hub.Scope().SetTag("request_id", chimiddleware.GetReqID(req.Context()))
			}
			w.Header().Set("X-Request-ID", chimiddleware.GetReqID(req.Context()))
			next.ServeHTTP(w, req)
		})
	})

	var cryptoEngine *crypto.Engine
	if cfg.EncryptionKey != "" {
		var err error
		cryptoEngine, err = crypto.New(cfg.EncryptionKey)
		if err != nil {
			panic("invalid encryption key: " + err.Error())
		}
	}

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"customkeys","phase":"9"}`))
	})

	h := &handler.Handler{
		Store:        cfg.DB,
		DB:           cfg.DB,
		Cache:        cfg.Cache,
		Crypto:       cryptoEngine,
		AuditHMACKey: []byte(cfg.AuditHMACKey),
		Hub:          cfg.Hub,
		Rotation:     cfg.Worker,
		Email:        cfg.Email,
	}

	jwtAuth := middleware.AuthMiddleware(cfg.JWTSecret, cfg.SupabaseURL, cfg.DB)
	flexAuth := middleware.FlexAuthMiddleware(cfg.JWTSecret, cfg.SupabaseURL, cfg.DB)

	// Plan-gating middleware shortcuts
	starterGate := requirePlan(cfg.DB, model.PlanStarter)
	businessGate := requirePlan(cfg.DB, model.PlanBusiness)

	r.Route("/v1", func(r chi.Router) {
		// Public webhook — no auth (verified by signature)
		r.Post("/webhooks/razorpay", h.RazorpayWebhook)

		// Public share link — no auth required
		r.Get("/share/{shareId}", h.GetSharedSecret)

		// Invitation accept (needs JWT but no org)
		r.With(jwtAuth).Get("/invitations/accept", h.AcceptInvitation)

		// Org setup
		r.With(jwtAuth).Post("/orgs", h.CreateOrg)
		r.With(jwtAuth).Get("/orgs/me", h.GetMyOrg)
		r.With(jwtAuth).Get("/me", h.GetMe)

		// Protected routes (require auth + org) — accepts both JWT and API token
		r.Group(func(r chi.Router) {
			r.Use(flexAuth)
			r.Use(middleware.RequireOrg)

			// ── Core (all plans) ──
			r.Get("/projects", h.ListProjects)
			r.Post("/projects", h.CreateProject)
			r.Get("/projects/{pid}", h.GetProject)
			r.Delete("/projects/{pid}", h.DeleteProject)

			r.Get("/projects/{pid}/envs", h.ListEnvironments)
			r.Post("/projects/{pid}/envs", h.CreateEnvironment)

			r.Get("/projects/{pid}/envs/{eid}/secrets", h.ListSecrets)
			r.Post("/projects/{pid}/envs/{eid}/secrets", h.CreateSecret)
			r.Get("/secrets/{sid}", h.GetSecret)
			r.Put("/secrets/{sid}", h.UpdateSecret)
			r.Delete("/secrets/{sid}", h.DeleteSecret)

			r.Get("/orgs/me/audit", h.ListAuditEvents)
			r.Get("/tokens", h.ListAPITokens)
			r.Post("/tokens", h.CreateAPIToken)
			r.Delete("/tokens/{tid}", h.RevokeAPIToken)

			// ── Secret sharing (Starter+) ──
			r.Group(func(r chi.Router) {
				r.Use(starterGate)
				r.Post("/share", h.CreateSharedSecret)
				r.Get("/share", h.ListSharedSecrets)
				r.Delete("/share/{shareId}", h.DeleteSharedSecret)
			})

			// ── Billing (all plans) ──
			r.Post("/billing/subscribe", h.CreateSubscription)
			r.Post("/billing/cancel", h.CancelSubscription)
			r.Post("/billing/coupons/redeem", h.RedeemCoupon)
			r.Get("/billing/status", h.GetSubscriptionStatus)
			r.Get("/orgs/me/usage", h.GetOrgUsage)

			// ── Members & Invitations (all plans, seat limits enforced in handler) ──
			r.Get("/orgs/me/members", h.ListMembers)
			r.Post("/orgs/me/invitations", h.InviteMember)
			r.Get("/orgs/me/invitations", h.ListInvitations)
			r.Delete("/orgs/me/invitations/{iid}", h.RevokeInvitation)

			// ── Starter+ features (rotation, versioning, websocket) ──
			r.Group(func(r chi.Router) {
				r.Use(starterGate)

				r.Get("/secrets/{sid}/versions", h.ListSecretVersions)

				// Rotation (Phase 2)
				r.Post("/secrets/{sid}/rotation", h.CreateRotationSchedule)
				r.Get("/secrets/{sid}/rotation", h.GetRotationSchedule)
				r.Delete("/rotation/{schedid}", h.DeleteRotationSchedule)
				r.Post("/secrets/{sid}/rotate", h.TriggerRotation)
				r.Get("/secrets/{sid}/rotation/history", h.ListRotationHistory)
			})

			// ── Business+ features (dynamic secrets, CI, approvals, analytics) ──
			r.Group(func(r chi.Router) {
				r.Use(businessGate)

				// Approvals (Phase 2)
				r.Get("/approvals", h.ListApprovals)
				r.Post("/approvals/{aid}/resolve", h.ResolveApproval)

				// Phase 3: Dynamic secrets
				r.Get("/projects/{pid}/envs/{eid}/dynamic", h.ListDynamicConfigs)
				r.Post("/projects/{pid}/envs/{eid}/dynamic", h.CreateDynamicConfig)
				r.Delete("/dynamic/{cfgid}", h.DeleteDynamicConfig)
				r.Post("/dynamic/{cfgid}/generate", h.GenerateDynamicSecret)
				r.Post("/dynamic/leases/{lid}/revoke", h.RevokeDynamicLease)
				r.Get("/orgs/me/dynamic/leases", h.ListDynamicLeases)

				// Phase 3: Analytics
				r.Get("/orgs/me/analytics/heatmap", h.GetSecretHeatmap)
				r.Get("/orgs/me/analytics/unused", h.GetUnusedSecrets)
				r.Get("/secrets/{sid}/analytics", h.GetSecretTimeSeries)

				// Phase 3: CI/CD integrations
				r.Get("/projects/{pid}/envs/{eid}/cicd-snippet", h.GetCICDSnippet)
				r.Post("/orgs/me/integrations", h.CreateIntegrationConfig)
				r.Get("/orgs/me/integrations", h.ListIntegrationConfigs)
				r.Delete("/orgs/me/integrations/{iid}", h.DeleteIntegrationConfig)
			})
		})

		// SDK/API token routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.APITokenMiddleware(cfg.DB))
			r.Use(middleware.RequireOrg)
			r.Get("/envs/{eid}/secrets/values", h.BulkPullSecrets)
		})

		// WebSocket (Phase 2) — requires Starter+
		r.Group(func(r chi.Router) {
			r.Use(middleware.APITokenMiddleware(cfg.DB))
			r.Get("/envs/{eid}/watch", func(w http.ResponseWriter, r *http.Request) {
				envID := chi.URLParam(r, "eid")
				if cfg.Hub != nil {
					cfg.Hub.ServeWS(w, r, envID)
				}
			})
		})
	})

	return r
}
