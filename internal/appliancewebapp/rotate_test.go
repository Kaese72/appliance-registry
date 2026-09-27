package appliancewebapp

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Kaese72/appliance-registry/internal/persistence"
	"github.com/Kaese72/appliance-registry/internal/tokens"
)

type fakeSecretWriter struct {
	written map[int64]string
	err     error
}

func (w *fakeSecretWriter) WriteApplianceSecret(_ context.Context, id int64, value string) error {
	if w.err != nil {
		return w.err
	}
	w.written[id] = value
	return nil
}

func (w *fakeSecretWriter) DeleteApplianceSecret(context.Context, int64) error { return nil }

func (d *fakeDB) SetApplianceSecretHash(_ context.Context, id int64, hash *string) error {
	if hash == nil {
		d.secretHash = ""
	} else {
		d.secretHash = *hash
	}
	return nil
}

type rotateInput = struct {
	Authorization string `header:"Authorization"`
	ApplianceID   int64  `path:"applianceId"`
}

func TestRotateOwnSecretIssuesANewSecretAndInvalidatesTheOldOne(t *testing.T) {
	h := newHarness(t)
	writer := &fakeSecretWriter{written: map[int64]string{}}
	h.app.secretWriter = writer

	res, err := h.app.RotateOwnSecret(context.Background(), &rotateInput{Authorization: "Bearer " + testSecret, ApplianceID: 1})
	if err != nil {
		t.Fatal(err)
	}
	fresh := res.Body.ApplianceSecret
	if fresh == "" || fresh == testSecret {
		t.Fatalf("expected a new secret, got %q", fresh)
	}
	if res.Body.Hostname == "" || res.Body.TunnelURL == "" {
		t.Fatalf("expected hostname and tunnel URL in the response, got %+v", res.Body)
	}
	// The cloud-side tunnel secret and the stored hash must both follow the new value.
	if writer.written[1] != fresh {
		t.Fatalf("cloud-connect secret not updated to the new value")
	}
	if h.db.secretHash != tokens.HashApplianceSecret(fresh) {
		t.Fatalf("stored hash does not match the new secret")
	}

	// The old secret is dead, the new one authenticates.
	_, err = h.app.RotateOwnSecret(context.Background(), &rotateInput{Authorization: "Bearer " + testSecret, ApplianceID: 1})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("old secret should be rejected with 401, got %v", err)
	}
	if _, err := h.app.CheckAccess(context.Background(), &accessInput{Authorization: "Bearer " + fresh, ApplianceID: 1, UserID: 7}); err != nil {
		t.Fatalf("new secret should authenticate: %v", err)
	}
}

func TestRotateOwnSecretRequiresTheApplianceSecret(t *testing.T) {
	h := newHarness(t)
	writer := &fakeSecretWriter{written: map[int64]string{}}
	h.app.secretWriter = writer

	tests := map[string]rotateInput{
		"no header":         {ApplianceID: 1},
		"wrong secret":      {Authorization: "Bearer appliance-1:wrong", ApplianceID: 1},
		"another appliance": {Authorization: "Bearer " + testSecret, ApplianceID: 2},
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			in := in
			_, err := h.app.RotateOwnSecret(context.Background(), &in)
			if statusOf(err) != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %v", err)
			}
		})
	}
	if len(writer.written) != 0 || h.db.secretHash != tokens.HashApplianceSecret(testSecret) {
		t.Fatal("a rejected rotation must not change any secret")
	}
}

func TestRotateOwnSecretRejectsARevokedAppliance(t *testing.T) {
	h := newHarness(t)
	h.app.secretWriter = &fakeSecretWriter{written: map[int64]string{}}
	h.db.appliance.Status = persistence.StatusRevoked

	_, err := h.app.RotateOwnSecret(context.Background(), &rotateInput{Authorization: "Bearer " + testSecret, ApplianceID: 1})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %v", err)
	}
}

// If the cloud-side Secret can't be written the appliance must keep a working
// secret, so it can simply try again.
func TestRotateOwnSecretKeepsTheOldSecretWhenProvisioningFails(t *testing.T) {
	h := newHarness(t)
	h.app.secretWriter = &fakeSecretWriter{written: map[int64]string{}, err: errors.New("apiserver down")}

	_, err := h.app.RotateOwnSecret(context.Background(), &rotateInput{Authorization: "Bearer " + testSecret, ApplianceID: 1})
	if statusOf(err) != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %v", err)
	}
	if h.db.secretHash != tokens.HashApplianceSecret(testSecret) {
		t.Fatal("the old secret must stay valid when provisioning failed")
	}
}
