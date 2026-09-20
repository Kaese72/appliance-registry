package appliancewebapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Kaese72/appliance-registry/internal/persistence"
	"github.com/Kaese72/appliance-registry/internal/tokens"
	"github.com/Kaese72/appliance-registry/internal/userregistry"
	"github.com/Kaese72/appliance-registry/restmodels"
	"github.com/Kaese72/cloud-user-registry/cloudtoken"
	"github.com/danielgtaylor/huma/v2"
)

const testSecret = "appliance-1:0123456789abcdef"

// fakeDB implements only what the login endpoints touch; calling anything else
// panics on the nil embedded interface, which is what we want in a test.
type fakeDB struct {
	persistence.ApplianceRegistryDB
	appliance  persistence.Appliance
	secretHash string
	codes      map[string]persistence.LoginCode
}

func (d *fakeDB) GetAppliance(_ context.Context, id int64) (persistence.Appliance, error) {
	if id != d.appliance.ID {
		return persistence.Appliance{}, sql.ErrNoRows
	}
	return d.appliance, nil
}

func (d *fakeDB) GetApplianceSecretHash(_ context.Context, id int64) (string, error) {
	if id != d.appliance.ID {
		return "", sql.ErrNoRows
	}
	return d.secretHash, nil
}

func (d *fakeDB) SaveLoginCode(_ context.Context, codeHash string, applianceID int64, userID int64, expiresAt time.Time) error {
	d.codes[codeHash] = persistence.LoginCode{CodeHash: codeHash, ApplianceID: applianceID, UserID: userID, ExpiresAt: expiresAt}
	return nil
}

func (d *fakeDB) ConsumeLoginCode(_ context.Context, codeHash string, applianceID int64) (persistence.LoginCode, error) {
	code, ok := d.codes[codeHash]
	if !ok || code.ApplianceID != applianceID {
		return persistence.LoginCode{}, sql.ErrNoRows
	}
	delete(d.codes, codeHash)
	return code, nil
}

type fakeUserRegistry struct {
	access userregistry.Access
	err    error
	// asked records the (groupID, userID) of the last lookup.
	askedGroup, askedUser int64
}

func (r *fakeUserRegistry) GetGroupMember(_ context.Context, groupID int64, userID int64) (userregistry.Access, error) {
	r.askedGroup, r.askedUser = groupID, userID
	return r.access, r.err
}

type harness struct {
	app webApp
	db  *fakeDB
	reg *fakeUserRegistry
	key *rsa.PrivateKey
}

func newHarness(t *testing.T) harness {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	db := &fakeDB{
		appliance:  persistence.Appliance{ID: 1, GroupID: 10, Status: persistence.StatusActive},
		secretHash: tokens.HashApplianceSecret(testSecret),
		codes:      map[string]persistence.LoginCode{},
	}
	reg := &fakeUserRegistry{access: userregistry.Access{IsMember: true, User: &userregistry.User{ID: 7, Username: "alice", Name: "Alice", Surname: "A", Email: "a@example.com"}}}
	app := NewWebApp(db, &key.PublicKey, nil, nil, time.Hour, 5*time.Minute, "appliance.example", nil, reg)
	return harness{app: app, db: db, reg: reg, key: key}
}

func statusOf(err error) int {
	var se huma.StatusError
	if errors.As(err, &se) {
		return se.GetStatus()
	}
	return 0
}

type accessInput = struct {
	Authorization string `header:"Authorization"`
	ApplianceID   int64  `path:"applianceId"`
	UserID        int64  `path:"userId"`
}

func TestCheckAccessRequiresTheApplianceSecret(t *testing.T) {
	h := newHarness(t)
	tests := map[string]string{
		"no header":    "",
		"wrong secret": "Bearer appliance-1:wrong",
		"not a bearer": testSecret,
	}
	for name, header := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := h.app.CheckAccess(context.Background(), &accessInput{Authorization: header, ApplianceID: 1, UserID: 7})
			if statusOf(err) != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %v", err)
			}
		})
	}
	if h.reg.askedUser != 0 {
		t.Error("cloud-user-registry must not be consulted before the appliance is authenticated")
	}
}

func TestCheckAccessRejectsApplianceWithoutStoredSecret(t *testing.T) {
	// An appliance enrolled before secret hashes existed has none stored, and
	// must not be authenticated by an empty comparison.
	h := newHarness(t)
	h.db.secretHash = ""
	_, err := h.app.CheckAccess(context.Background(), &accessInput{Authorization: "Bearer ", ApplianceID: 1, UserID: 7})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %v", err)
	}
}

func TestCheckAccessCannotBeUsedForAnotherAppliance(t *testing.T) {
	h := newHarness(t)
	_, err := h.app.CheckAccess(context.Background(), &accessInput{Authorization: "Bearer " + testSecret, ApplianceID: 2, UserID: 7})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %v", err)
	}
}

func TestCheckAccessRevokedApplianceIsRejected(t *testing.T) {
	h := newHarness(t)
	h.db.appliance.Status = persistence.StatusRevoked
	_, err := h.app.CheckAccess(context.Background(), &accessInput{Authorization: "Bearer " + testSecret, ApplianceID: 1, UserID: 7})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %v", err)
	}
}

func TestCheckAccessAllowedAndDenied(t *testing.T) {
	h := newHarness(t)
	res, err := h.app.CheckAccess(context.Background(), &accessInput{Authorization: "Bearer " + testSecret, ApplianceID: 1, UserID: 7})
	if err != nil || !res.Body.Allowed {
		t.Fatalf("expected allowed, got %v %v", res, err)
	}
	if h.reg.askedGroup != 10 || h.reg.askedUser != 7 {
		t.Errorf("membership must be checked against the appliance's owning group, asked group %d user %d", h.reg.askedGroup, h.reg.askedUser)
	}

	h.reg.access = userregistry.Access{IsMember: false}
	res, err = h.app.CheckAccess(context.Background(), &accessInput{Authorization: "Bearer " + testSecret, ApplianceID: 1, UserID: 7})
	if err != nil || res.Body.Allowed {
		t.Fatalf("expected denied, got %v %v", res, err)
	}
}

func TestCheckAccessUserRegistryDownIsBadGatewayNotDenied(t *testing.T) {
	h := newHarness(t)
	h.reg.err = errors.New("connection refused")
	_, err := h.app.CheckAccess(context.Background(), &accessInput{Authorization: "Bearer " + testSecret, ApplianceID: 1, UserID: 7})
	if statusOf(err) != http.StatusBadGateway {
		t.Fatalf("expected 502 so the appliance can tell unknown from denied, got %v", err)
	}
}

type createInput = struct {
	Authorization string `header:"Authorization"`
	ApplianceID   int64  `path:"applianceId"`
}

type restmodelsRedeem = restmodels.RedeemLoginCodeRequest

type redeemInput = struct {
	Authorization string `header:"Authorization"`
	ApplianceID   int64  `path:"applianceId"`
	Body          restmodelsRedeem
}

func (h harness) useToken(t *testing.T, userID, groupID int64) string {
	t.Helper()
	tok, err := cloudtoken.Sign(h.key, userID, groupID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return "Bearer " + tok
}

func TestCreateLoginCodeOnlyForOwningGroup(t *testing.T) {
	h := newHarness(t)

	_, err := h.app.CreateLoginCode(context.Background(), &createInput{Authorization: h.useToken(t, 7, 99), ApplianceID: 1})
	if statusOf(err) != http.StatusNotFound {
		t.Fatalf("a member of a different group must get 404, got %v", err)
	}
	if len(h.db.codes) != 0 {
		t.Error("no code may be issued to a caller outside the owning group")
	}

	res, err := h.app.CreateLoginCode(context.Background(), &createInput{Authorization: h.useToken(t, 7, 10), ApplianceID: 1})
	if err != nil || res.Body.Code == "" {
		t.Fatalf("expected a code for the owning group, got %v", err)
	}
	stored, ok := h.db.codes[tokens.HashExchangeCode(res.Body.Code)]
	if !ok || stored.UserID != 7 || stored.ApplianceID != 1 {
		t.Errorf("code must be stored hashed and bound to user 7 / appliance 1, got %+v (found=%v)", stored, ok)
	}
}

func TestCreateLoginCodeRequiresActiveAppliance(t *testing.T) {
	h := newHarness(t)
	h.db.appliance.Status = persistence.StatusPending
	_, err := h.app.CreateLoginCode(context.Background(), &createInput{Authorization: h.useToken(t, 7, 10), ApplianceID: 1})
	if statusOf(err) != http.StatusConflict {
		t.Fatalf("expected 409, got %v", err)
	}
}

func TestCreateLoginCodeRejectsRefreshTokenStyleAuth(t *testing.T) {
	h := newHarness(t)
	_, err := h.app.CreateLoginCode(context.Background(), &createInput{Authorization: "Bearer " + testSecret, ApplianceID: 1})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("an appliance secret must not be accepted as a user token, got %v", err)
	}
}

func TestRedeemLoginCodeIsSingleUseAndNeedsTheSecret(t *testing.T) {
	h := newHarness(t)
	created, err := h.app.CreateLoginCode(context.Background(), &createInput{Authorization: h.useToken(t, 7, 10), ApplianceID: 1})
	if err != nil {
		t.Fatal(err)
	}
	code := created.Body.Code

	// Someone who intercepted the code in the redirect but lacks the secret.
	_, err = h.app.RedeemLoginCode(context.Background(), &redeemInput{Authorization: "Bearer appliance-1:wrong", ApplianceID: 1, Body: restmodelsRedeem{Code: code}})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401 without the appliance secret, got %v", err)
	}
	if len(h.db.codes) != 1 {
		t.Fatal("a failed redemption attempt must not consume the code")
	}

	res, err := h.app.RedeemLoginCode(context.Background(), &redeemInput{Authorization: "Bearer " + testSecret, ApplianceID: 1, Body: restmodelsRedeem{Code: code}})
	if err != nil || res.Body.ID != 7 || res.Body.Username != "alice" {
		t.Fatalf("expected alice, got %+v %v", res, err)
	}

	_, err = h.app.RedeemLoginCode(context.Background(), &redeemInput{Authorization: "Bearer " + testSecret, ApplianceID: 1, Body: restmodelsRedeem{Code: code}})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("a code must be single-use, got %v", err)
	}
}

func TestRedeemLoginCodeExpired(t *testing.T) {
	h := newHarness(t)
	h.db.codes[tokens.HashExchangeCode("old")] = persistence.LoginCode{CodeHash: tokens.HashExchangeCode("old"), ApplianceID: 1, UserID: 7, ExpiresAt: time.Now().Add(-time.Minute)}
	_, err := h.app.RedeemLoginCode(context.Background(), &redeemInput{Authorization: "Bearer " + testSecret, ApplianceID: 1, Body: restmodelsRedeem{Code: "old"}})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an expired code, got %v", err)
	}
}

func TestRedeemLoginCodeRechecksMembership(t *testing.T) {
	// The user was removed from the group between getting the code and the
	// appliance redeeming it.
	h := newHarness(t)
	created, err := h.app.CreateLoginCode(context.Background(), &createInput{Authorization: h.useToken(t, 7, 10), ApplianceID: 1})
	if err != nil {
		t.Fatal(err)
	}
	h.reg.access = userregistry.Access{IsMember: false}

	_, err = h.app.RedeemLoginCode(context.Background(), &redeemInput{Authorization: "Bearer " + testSecret, ApplianceID: 1, Body: restmodelsRedeem{Code: created.Body.Code}})
	if statusOf(err) != http.StatusForbidden {
		t.Fatalf("expected 403, got %v", err)
	}
}
