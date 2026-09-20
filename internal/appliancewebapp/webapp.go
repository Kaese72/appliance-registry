package appliancewebapp

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"strconv"
	"time"

	"github.com/Kaese72/appliance-registry/internal/hostnames"
	"github.com/Kaese72/appliance-registry/internal/k8ssecrets"
	"github.com/Kaese72/appliance-registry/internal/logging"
	"github.com/Kaese72/appliance-registry/internal/persistence"
	"github.com/Kaese72/appliance-registry/internal/tokens"
	"github.com/Kaese72/appliance-registry/internal/userregistry"
	"github.com/Kaese72/appliance-registry/restmodels"
	"github.com/Kaese72/cloud-user-registry/cloudtoken"
	"github.com/danielgtaylor/huma/v2"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/time/rate"
)

// maxHostnameLabelAttempts bounds retries when a randomly generated
// hostname label collides with an existing one - see hostnames.GenerateLabel.
const maxHostnameLabelAttempts = 5

// pluginRateLimit and pluginRateBurst throttle PluginGetParams, the one
// endpoint on this service reachable from the public internet behind a
// single static bearer token (see AuthConfig's doc comment on why it's a
// separate token from the generic service-token path). Its only legitimate
// caller is the ApplicationSet's own requeueAfterSeconds poll - see
// huemie-gitops-base's cloud/application-crds - which is far slower than
// this, so the limit only ever bites a token-guessing attempt, not real
// traffic.
var pluginRateLimit = rate.Every(5 * time.Second)

const pluginRateBurst = 2

type webApp struct {
	persistence        persistence.ApplianceRegistryDB
	publicKey          *rsa.PublicKey
	serviceTokens      []string
	pluginTokens       []string
	pluginLimiter      *rate.Limiter
	claimTokenExpiry   time.Duration
	exchangeCodeExpiry time.Duration
	baseDomain         string
	secretWriter       k8ssecrets.SecretWriter
	userRegistry       userregistry.Client
}

func NewWebApp(
	p persistence.ApplianceRegistryDB,
	publicKey *rsa.PublicKey,
	serviceTokens []string,
	pluginTokens []string,
	claimTokenExpiry time.Duration,
	exchangeCodeExpiry time.Duration,
	baseDomain string,
	secretWriter k8ssecrets.SecretWriter,
	userRegistry userregistry.Client,
) webApp {
	return webApp{
		persistence:        p,
		publicKey:          publicKey,
		serviceTokens:      serviceTokens,
		pluginTokens:       pluginTokens,
		pluginLimiter:      rate.NewLimiter(pluginRateLimit, pluginRateBurst),
		claimTokenExpiry:   claimTokenExpiry,
		exchangeCodeExpiry: exchangeCodeExpiry,
		baseDomain:         baseDomain,
		secretWriter:       secretWriter,
		userRegistry:       userRegistry,
	}
}

// storeSecretHash records the hash of a freshly generated appliance secret so
// the appliance can later authenticate itself - see authenticateAppliance.
func (app webApp) storeSecretHash(ctx context.Context, applianceID int64, secret string) error {
	hash := tokens.HashApplianceSecret(secret)
	return app.persistence.SetApplianceSecretHash(ctx, applianceID, &hash)
}

// authenticateAppliance verifies that the request's bearer token is the
// current secret of the appliance named in the path, and that the appliance is
// active. Every failure is reported as 401 so the endpoint doesn't reveal
// whether an appliance id exists or what state it is in.
func (app webApp) authenticateAppliance(ctx context.Context, applianceID int64, authHeader string) (persistence.Appliance, error) {
	secret, err := tokens.ApplianceSecretFromAuthHeader(authHeader)
	if err != nil {
		return persistence.Appliance{}, huma.Error401Unauthorized("missing appliance secret")
	}
	stored, err := app.persistence.GetApplianceSecretHash(ctx, applianceID)
	if err != nil {
		if err == sql.ErrNoRows {
			return persistence.Appliance{}, huma.Error401Unauthorized("invalid appliance secret")
		}
		logging.ErrorErr(err, ctx)
		return persistence.Appliance{}, huma.Error500InternalServerError("failed to look up appliance secret")
	}
	if stored == "" || subtle.ConstantTimeCompare([]byte(tokens.HashApplianceSecret(secret)), []byte(stored)) != 1 {
		return persistence.Appliance{}, huma.Error401Unauthorized("invalid appliance secret")
	}
	appliance, err := app.persistence.GetAppliance(ctx, applianceID)
	if err != nil {
		if err == sql.ErrNoRows {
			return persistence.Appliance{}, huma.Error401Unauthorized("invalid appliance secret")
		}
		logging.ErrorErr(err, ctx)
		return persistence.Appliance{}, huma.Error500InternalServerError("failed to look up appliance")
	}
	if appliance.Status != persistence.StatusActive {
		return persistence.Appliance{}, huma.Error401Unauthorized("invalid appliance secret")
	}
	return appliance, nil
}

func (app webApp) hostname(a persistence.Appliance) string {
	return hostnames.FullHostname(a.HostnameLabel, app.baseDomain)
}

func (app webApp) toApplianceResponse(a persistence.Appliance) restmodels.ApplianceResponse {
	return restmodels.ApplianceResponse{
		ID:         a.ID,
		Name:       a.Name,
		Hostname:   app.hostname(a),
		Status:     string(a.Status),
		CreatedAt:  a.CreatedAt,
		ClaimedAt:  a.ClaimedAt,
		LastSeenAt: a.LastSeenAt,
	}
}

// tunnelURL is passed straight through to the appliance's chisel client as
// its server address (see cloud-connect/client's tunnel supervisor). chisel
// does its own http->ws / https->wss upgrade and only recognizes an "http"
// prefix on the server address - handing it "wss://" directly breaks its
// URL parsing (host ends up as the literal string "wss:").
func (app webApp) tunnelURL(a persistence.Appliance) string {
	return fmt.Sprintf("https://%s/cloud-connect/v0/tunnel", app.hostname(a))
}

// requireOwningGroup fetches the Appliance and checks that it is owned by
// groupID. A mismatch (or a nonexistent appliance) is reported as 404, not
// 403, so the endpoint doesn't leak the existence of appliances owned by
// other Groups - see the README's "Revocation / rotation".
//
// This only proves the caller's use token carries the owning group id, not
// that they're specifically an admin of it: a use token only carries
// {id, groupId}, with no admin flag, and this service has no access to
// cloud-user-registry's membership table to look one up. See the README's
// "Architecture" section.
func (app webApp) requireOwningGroup(ctx context.Context, applianceID int64, groupID int64) (persistence.Appliance, error) {
	a, err := app.persistence.GetAppliance(ctx, applianceID)
	if err != nil {
		if err == sql.ErrNoRows {
			return persistence.Appliance{}, huma.Error404NotFound("appliance not found")
		}
		logging.ErrorErr(err, ctx)
		return persistence.Appliance{}, huma.Error500InternalServerError("failed to look up appliance")
	}
	if a.GroupID != groupID {
		return persistence.Appliance{}, huma.Error404NotFound("appliance not found")
	}
	return a, nil
}

// createApplianceWithRetry inserts a new pending Appliance for groupID,
// retrying with a freshly generated hostname label on a collision - shared
// by Register and Enroll, which differ only in what credential they hand
// back afterwards.
func (app webApp) createApplianceWithRetry(ctx context.Context, name string, groupID int64) (persistence.Appliance, error) {
	var appliance persistence.Appliance
	for attempt := 0; ; attempt++ {
		label, err := hostnames.GenerateLabel(name)
		if err != nil {
			return persistence.Appliance{}, err
		}
		appliance, err = app.persistence.CreateAppliance(ctx, name, label, groupID)
		if err == nil {
			return appliance, nil
		}
		if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 && attempt < maxHostnameLabelAttempts-1 {
			continue
		}
		return persistence.Appliance{}, err
	}
}

// issueClaimToken generates and persists a fresh claim token for appliance,
// replacing any existing one - shared by Register and Enroll.
func (app webApp) issueClaimToken(ctx context.Context, applianceID int64) (rawToken string, hash string, expiresAt time.Time, err error) {
	rawToken, hash, err = tokens.GenerateClaimToken()
	if err != nil {
		return "", "", time.Time{}, err
	}
	expiresAt = time.Now().Add(app.claimTokenExpiry)
	if err := app.persistence.SaveClaimToken(ctx, applianceID, hash, expiresAt); err != nil {
		return "", "", time.Time{}, err
	}
	return rawToken, hash, expiresAt, nil
}

// Register creates a new pending Appliance owned by the caller's current
// group and issues its one-time claim token - see the README's
// "Registration".
func (app webApp) Register(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	Body          restmodels.RegisterApplianceRequest
}) (*struct {
	Body restmodels.RegisterApplianceResponse
}, error) {
	_, groupID, err := cloudtoken.FromAuthHeader(app.publicKey, input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}

	appliance, err := app.createApplianceWithRetry(ctx, input.Body.Name, groupID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to register appliance")
	}

	rawToken, _, expiresAt, err := app.issueClaimToken(ctx, appliance.ID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to issue claim token")
	}

	return &struct {
		Body restmodels.RegisterApplianceResponse
	}{
		Body: restmodels.RegisterApplianceResponse{
			ApplianceResponse:   app.toApplianceResponse(appliance),
			ClaimToken:          rawToken,
			ClaimTokenExpiresAt: expiresAt,
		},
	}, nil
}

// Enroll is the browser-facing counterpart to Register, used by cloud-ui's
// enrollment redirect page (see the README's "Enrollment" section). It
// registers a new pending Appliance exactly like Register, but instead of
// handing the raw claim token back to the browser, it wraps it in a
// short-lived, single-use exchange code: the browser never sees the claim
// token, only the code, which it hands off to the appliance itself via the
// return_to redirect. The appliance then redeems the code server-to-server
// at EnrollRedeem.
func (app webApp) Enroll(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	Body          restmodels.RegisterApplianceRequest
}) (*struct {
	Body restmodels.EnrollApplianceResponse
}, error) {
	_, groupID, err := cloudtoken.FromAuthHeader(app.publicKey, input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}

	appliance, err := app.createApplianceWithRetry(ctx, input.Body.Name, groupID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to register appliance")
	}

	_, claimTokenHash, _, err := app.issueClaimToken(ctx, appliance.ID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to issue claim token")
	}

	rawCode, codeHash, err := tokens.GenerateExchangeCode()
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to generate exchange code")
	}
	expiresAt := time.Now().Add(app.exchangeCodeExpiry)
	if err := app.persistence.SaveEnrollExchangeCode(ctx, appliance.ID, codeHash, claimTokenHash, expiresAt); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to issue exchange code")
	}

	return &struct {
		Body restmodels.EnrollApplianceResponse
	}{
		Body: restmodels.EnrollApplianceResponse{
			ApplianceID:           appliance.ID,
			ExchangeCode:          rawCode,
			ExchangeCodeExpiresAt: expiresAt,
		},
	}, nil
}

// ListAppliances serves two distinct callers on the one route - see the
// README's "Listing" section:
//   - a generic internal service caller, authenticated with one of
//     serviceTokens, always gets every active Appliance regardless of
//     owner, with no secret material in the response. The ArgoCD
//     ApplicationSet Plugin generator does NOT use this path - it has its
//     own dedicated endpoint and token set, PluginGetParams, since it's
//     reachable over the public internet;
//   - a logged-in user, authenticated with a use token, gets only the
//     Appliances owned by their current group, optionally filtered by
//     ?status=. Revoked appliances are omitted unless ?includeRevoked=true
//     (an explicit ?status=revoked also returns them).
func (app webApp) ListAppliances(ctx context.Context, input *struct {
	Authorization  string `header:"Authorization"`
	Status         string `query:"status"`
	IncludeRevoked bool   `query:"includeRevoked"`
}) (*struct {
	Body []restmodels.ApplianceResponse
}, error) {
	if err := tokens.CheckServiceTokens(app.serviceTokens, input.Authorization); err == nil {
		appliances, err := app.persistence.ListAppliancesByStatus(ctx, persistence.StatusActive)
		if err != nil {
			logging.ErrorErr(err, ctx)
			return nil, huma.Error500InternalServerError("failed to list appliances")
		}
		return app.applianceListResponse(appliances), nil
	}

	_, groupID, err := cloudtoken.FromAuthHeader(app.publicKey, input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	appliances, err := app.persistence.ListAppliancesForGroup(ctx, groupID, persistence.ApplianceFilter{
		Status:         persistence.ApplianceStatus(input.Status),
		IncludeRevoked: input.IncludeRevoked,
	})
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to list appliances")
	}
	return app.applianceListResponse(appliances), nil
}

func (app webApp) applianceListResponse(appliances []persistence.Appliance) *struct {
	Body []restmodels.ApplianceResponse
} {
	resp := make([]restmodels.ApplianceResponse, len(appliances))
	for i, a := range appliances {
		resp[i] = app.toApplianceResponse(a)
	}
	return &struct {
		Body []restmodels.ApplianceResponse
	}{Body: resp}
}

// Claim is called exactly once by a freshly-installed appliance, bearing
// the claim token it was given at registration instead of a use token -
// see the README's "Claiming".
func (app webApp) Claim(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	ApplianceID   int64  `path:"applianceId"`
}) (*struct {
	Body restmodels.ClaimApplianceResponse
}, error) {
	rawToken, err := tokens.ClaimTokenFromAuthHeader(input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing claim token")
	}
	stored, err := app.persistence.GetClaimToken(ctx, input.ApplianceID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error401Unauthorized("invalid or expired claim token")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to look up claim token")
	}
	if time.Now().After(stored.ExpiresAt) {
		_ = app.persistence.DeleteClaimToken(ctx, input.ApplianceID)
		return nil, huma.Error401Unauthorized("invalid or expired claim token")
	}
	if subtle.ConstantTimeCompare([]byte(tokens.HashClaimToken(rawToken)), []byte(stored.TokenHash)) != 1 {
		return nil, huma.Error401Unauthorized("invalid or expired claim token")
	}

	appliance, err := app.persistence.GetAppliance(ctx, input.ApplianceID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error404NotFound("appliance not found")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to look up appliance")
	}
	if appliance.Status != persistence.StatusPending {
		return nil, huma.Error409Conflict("appliance has already been claimed")
	}

	secret, err := tokens.GenerateApplianceSecret(appliance.ID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to generate appliance secret")
	}
	if err := app.secretWriter.WriteApplianceSecret(ctx, appliance.ID, secret); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to provision cloud-connect secret")
	}
	if err := app.storeSecretHash(ctx, appliance.ID, secret); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to persist appliance secret hash")
	}
	if err := app.persistence.MarkApplianceClaimed(ctx, appliance.ID); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to mark appliance claimed")
	}
	if err := app.persistence.DeleteClaimToken(ctx, appliance.ID); err != nil {
		logging.ErrorErr(err, ctx)
		// Non-fatal: the token is scoped to a now-active appliance, so a
		// leftover row can no longer be used to re-claim it (the status
		// check above would reject that), only to leak that this appliance
		// exists - already true of any appliance id.
	}

	return &struct {
		Body restmodels.ClaimApplianceResponse
	}{
		Body: restmodels.ClaimApplianceResponse{
			ApplianceSecret: secret,
			Hostname:        app.hostname(appliance),
			TunnelURL:       app.tunnelURL(appliance),
		},
	}, nil
}

// EnrollRedeem is the server-to-server counterpart to Enroll, called once by
// the appliance's own cloud-connect-client using the exchange code its
// local UI received via the browser redirect (see the README's "Enrollment"
// section). It performs exactly the same state transition as Claim -
// generate the appliance secret, write it to k8s (still required: the
// cloud-side cloud-connect-server reads it from there), mark the appliance
// claimed - but authenticates with the exchange code instead of the claim
// token, and additionally checks that the code's pinned claimTokenHash
// still matches the appliance's live claim token, so a code can't be
// redeemed after that claim token has been superseded (e.g. by a second
// enroll attempt for the same appliance).
func (app webApp) EnrollRedeem(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	ApplianceID   int64  `path:"applianceId"`
}) (*struct {
	Body restmodels.ClaimApplianceResponse
}, error) {
	rawCode, err := tokens.ClaimTokenFromAuthHeader(input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing exchange code")
	}
	exchangeCode, err := app.persistence.GetEnrollExchangeCode(ctx, input.ApplianceID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error401Unauthorized("invalid or expired exchange code")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to look up exchange code")
	}
	if time.Now().After(exchangeCode.ExpiresAt) {
		_ = app.persistence.DeleteEnrollExchangeCode(ctx, input.ApplianceID)
		return nil, huma.Error401Unauthorized("invalid or expired exchange code")
	}
	if subtle.ConstantTimeCompare([]byte(tokens.HashExchangeCode(rawCode)), []byte(exchangeCode.CodeHash)) != 1 {
		return nil, huma.Error401Unauthorized("invalid or expired exchange code")
	}

	claimToken, err := app.persistence.GetClaimToken(ctx, input.ApplianceID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error401Unauthorized("invalid or expired exchange code")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to look up claim token")
	}
	if subtle.ConstantTimeCompare([]byte(exchangeCode.ClaimTokenHash), []byte(claimToken.TokenHash)) != 1 {
		return nil, huma.Error401Unauthorized("invalid or expired exchange code")
	}

	appliance, err := app.persistence.GetAppliance(ctx, input.ApplianceID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error404NotFound("appliance not found")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to look up appliance")
	}
	if appliance.Status != persistence.StatusPending {
		return nil, huma.Error409Conflict("appliance has already been claimed")
	}

	secret, err := tokens.GenerateApplianceSecret(appliance.ID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to generate appliance secret")
	}
	if err := app.secretWriter.WriteApplianceSecret(ctx, appliance.ID, secret); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to provision cloud-connect secret")
	}
	if err := app.storeSecretHash(ctx, appliance.ID, secret); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to persist appliance secret hash")
	}
	if err := app.persistence.MarkApplianceClaimed(ctx, appliance.ID); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to mark appliance claimed")
	}
	if err := app.persistence.DeleteClaimToken(ctx, appliance.ID); err != nil {
		logging.ErrorErr(err, ctx)
		// Non-fatal - see the same comment in Claim.
	}
	if err := app.persistence.DeleteEnrollExchangeCode(ctx, appliance.ID); err != nil {
		logging.ErrorErr(err, ctx)
		// Non-fatal, for the same reason: the code is scoped to a now-active
		// appliance and can no longer be used to re-redeem it.
	}

	return &struct {
		Body restmodels.ClaimApplianceResponse
	}{
		Body: restmodels.ClaimApplianceResponse{
			ApplianceSecret: secret,
			Hostname:        app.hostname(appliance),
			TunnelURL:       app.tunnelURL(appliance),
		},
	}, nil
}

// Revoke withdraws an Appliance's access - see the README's
// "Revocation / rotation".
func (app webApp) Revoke(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	ApplianceID   int64  `path:"applianceId"`
}) (*struct{}, error) {
	_, groupID, err := cloudtoken.FromAuthHeader(app.publicKey, input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	appliance, err := app.requireOwningGroup(ctx, input.ApplianceID, groupID)
	if err != nil {
		return nil, err
	}
	if err := app.persistence.SetApplianceStatus(ctx, appliance.ID, persistence.StatusRevoked); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to revoke appliance")
	}
	if err := app.secretWriter.DeleteApplianceSecret(ctx, appliance.ID); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to remove cloud-connect secret")
	}
	if err := app.persistence.SetApplianceSecretHash(ctx, appliance.ID, nil); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to clear appliance secret hash")
	}
	_ = app.persistence.DeleteClaimToken(ctx, appliance.ID)
	return &struct{}{}, nil
}

// CreateLoginCode is the browser-facing first leg of cloud login, called from
// cloud-ui's appliance-login redirect page once the user is authenticated. It
// issues a short-lived, single-use login code if - and only if - the caller's
// use token carries the appliance's owning group, i.e. the caller is a member
// of that group. The browser then carries the code to the appliance, which
// redeems it server-to-server at RedeemLoginCode.
func (app webApp) CreateLoginCode(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	ApplianceID   int64  `path:"applianceId"`
}) (*struct {
	Body restmodels.LoginCodeResponse
}, error) {
	userID, groupID, err := cloudtoken.FromAuthHeader(app.publicKey, input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	appliance, err := app.requireOwningGroup(ctx, input.ApplianceID, groupID)
	if err != nil {
		return nil, err
	}
	if appliance.Status != persistence.StatusActive {
		return nil, huma.Error409Conflict("appliance is not active")
	}
	rawCode, codeHash, err := tokens.GenerateExchangeCode()
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to generate login code")
	}
	expiresAt := time.Now().Add(app.exchangeCodeExpiry)
	if err := app.persistence.SaveLoginCode(ctx, codeHash, appliance.ID, userID, expiresAt); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to issue login code")
	}
	return &struct {
		Body restmodels.LoginCodeResponse
	}{Body: restmodels.LoginCodeResponse{Code: rawCode, ExpiresAt: expiresAt}}, nil
}

// RedeemLoginCode is the server-to-server second leg of cloud login, called
// by the appliance itself, authenticating with its appliance secret. It
// consumes the login code, re-verifies the user is still a member of the
// appliance's owning group, and returns their cloud identity. The code alone
// is useless without the secret, so leaking it through the browser redirect
// does not let anyone else log in.
func (app webApp) RedeemLoginCode(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	ApplianceID   int64  `path:"applianceId"`
	Body          restmodels.RedeemLoginCodeRequest
}) (*struct {
	Body restmodels.CloudUserResponse
}, error) {
	appliance, err := app.authenticateAppliance(ctx, input.ApplianceID, input.Authorization)
	if err != nil {
		return nil, err
	}
	code, err := app.persistence.ConsumeLoginCode(ctx, tokens.HashExchangeCode(input.Body.Code), appliance.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error401Unauthorized("invalid or expired login code")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to look up login code")
	}
	if time.Now().After(code.ExpiresAt) {
		return nil, huma.Error401Unauthorized("invalid or expired login code")
	}
	access, err := app.userRegistry.GetGroupMember(ctx, appliance.GroupID, code.UserID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error502BadGateway("failed to verify group membership")
	}
	if !access.IsMember || access.User == nil {
		return nil, huma.Error403Forbidden("user no longer has access to this appliance")
	}
	return &struct {
		Body restmodels.CloudUserResponse
	}{Body: restmodels.CloudUserResponse{
		ID:       access.User.ID,
		Username: access.User.Username,
		Name:     access.User.Name,
		Surname:  access.User.Surname,
		Email:    access.User.Email,
	}}, nil
}

// CheckAccess lets an appliance ask whether a cloud user who logged in
// earlier still has access to it - the appliance calls this whenever it is
// asked to refresh that user's session. A user has access iff the appliance is
// active and they are still a member of its owning group. An authentication
// failure (rotated or revoked secret) is a 401 rather than allowed=false, so
// the appliance can tell "denied" from "my credentials are stale".
func (app webApp) CheckAccess(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	ApplianceID   int64  `path:"applianceId"`
	UserID        int64  `path:"userId"`
}) (*struct {
	Body restmodels.ApplianceAccessResponse
}, error) {
	appliance, err := app.authenticateAppliance(ctx, input.ApplianceID, input.Authorization)
	if err != nil {
		return nil, err
	}
	access, err := app.userRegistry.GetGroupMember(ctx, appliance.GroupID, input.UserID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error502BadGateway("failed to verify group membership")
	}
	return &struct {
		Body restmodels.ApplianceAccessResponse
	}{Body: restmodels.ApplianceAccessResponse{Allowed: access.IsMember}}, nil
}

// RotateSecret generates a fresh Appliance secret without changing the
// hostname or status - see the README's "Revocation / rotation". Only
// meaningful for an already-claimed (active) appliance.
func (app webApp) RotateSecret(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	ApplianceID   int64  `path:"applianceId"`
}) (*struct {
	Body restmodels.ClaimApplianceResponse
}, error) {
	_, groupID, err := cloudtoken.FromAuthHeader(app.publicKey, input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	appliance, err := app.requireOwningGroup(ctx, input.ApplianceID, groupID)
	if err != nil {
		return nil, err
	}
	if appliance.Status != persistence.StatusActive {
		return nil, huma.Error409Conflict("only an active appliance's secret can be rotated")
	}
	secret, err := tokens.GenerateApplianceSecret(appliance.ID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to generate appliance secret")
	}
	if err := app.secretWriter.WriteApplianceSecret(ctx, appliance.ID, secret); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to provision cloud-connect secret")
	}
	if err := app.storeSecretHash(ctx, appliance.ID, secret); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to persist appliance secret hash")
	}
	return &struct {
		Body restmodels.ClaimApplianceResponse
	}{
		Body: restmodels.ClaimApplianceResponse{
			ApplianceSecret: secret,
			Hostname:        app.hostname(appliance),
			TunnelURL:       app.tunnelURL(appliance),
		},
	}, nil
}

// PluginGetParams implements ArgoCD's ApplicationSet Plugin generator
// protocol (POST .../api/v1/getparams.execute) directly, rather than
// standing up a separate plugin service - see huemie-gitops-base's
// cloud/application-crds/applicationset-cloud-connect-server-fleet.yaml,
// which polls this endpoint to instantiate one cloud-connect-server-<id>
// per active Appliance. Authenticated with its own dedicated pluginTokens
// (not the generic serviceTokens ListAppliances uses) since this endpoint,
// unlike the rest of this service, is reachable over the public internet -
// see AuthConfig's doc comment. Rate-limited for the same reason: it's a
// single static bearer token sitting on the open internet, so it needs its
// own defense against being brute-forced, independent of whatever's in
// front of the rest of this service.
func (app webApp) PluginGetParams(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	Body          restmodels.ArgoCDPluginGetParamsRequest
}) (*struct {
	Body restmodels.ArgoCDPluginGetParamsResponse
}, error) {
	if !app.pluginLimiter.Allow() {
		return nil, huma.Error429TooManyRequests("rate limit exceeded")
	}
	if err := tokens.CheckServiceTokens(app.pluginTokens, input.Authorization); err != nil {
		return nil, huma.Error401Unauthorized("invalid service token")
	}
	appliances, err := app.persistence.ListAppliancesByStatus(ctx, persistence.StatusActive)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to list appliances")
	}
	resp := restmodels.ArgoCDPluginGetParamsResponse{}
	resp.Output.Parameters = make([]restmodels.ArgoCDPluginParameter, len(appliances))
	for i, a := range appliances {
		resp.Output.Parameters[i] = restmodels.ArgoCDPluginParameter{
			ID:       strconv.FormatInt(a.ID, 10),
			Hostname: app.hostname(a),
			Name:     a.Name,
		}
	}
	return &struct {
		Body restmodels.ArgoCDPluginGetParamsResponse
	}{Body: resp}, nil
}
