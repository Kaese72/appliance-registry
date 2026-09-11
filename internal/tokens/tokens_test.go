package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func mustKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestValidateUseTokenRoundTrip(t *testing.T) {
	key := mustKey(t)
	claims := jwt.MapClaims{
		"id":      float64(42),
		"groupId": float64(7),
		"exp":     time.Now().Add(time.Minute).Unix(),
		"iat":     time.Now().Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	userID, groupID, err := ValidateUseToken(&key.PublicKey, signed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID != 42 || groupID != 7 {
		t.Fatalf("got userID=%d groupID=%d, want 42/7", userID, groupID)
	}
}

func TestValidateUseTokenRejectsWrongKey(t *testing.T) {
	key := mustKey(t)
	other := mustKey(t)
	claims := jwt.MapClaims{"id": float64(1), "groupId": float64(1), "exp": time.Now().Add(time.Minute).Unix()}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ValidateUseToken(&other.PublicKey, signed); err == nil {
		t.Fatal("expected signature verification to fail with the wrong public key")
	}
}

func TestValidateUseTokenRejectsExpired(t *testing.T) {
	key := mustKey(t)
	claims := jwt.MapClaims{"id": float64(1), "groupId": float64(1), "exp": time.Now().Add(-time.Minute).Unix()}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ValidateUseToken(&key.PublicKey, signed); err == nil {
		t.Fatal("expected an expired token to be rejected")
	}
}

func TestGenerateClaimTokenHashRoundTrip(t *testing.T) {
	raw, hash, err := GenerateClaimToken()
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || hash == "" {
		t.Fatal("expected non-empty raw token and hash")
	}
	if HashClaimToken(raw) != hash {
		t.Fatal("hashing the raw token again should reproduce the same hash")
	}
	raw2, _, err := GenerateClaimToken()
	if err != nil {
		t.Fatal(err)
	}
	if raw2 == raw {
		t.Fatal("two generated claim tokens should not collide")
	}
}

func TestCheckServiceTokens(t *testing.T) {
	valid := []string{"old-secret", "new-secret"}
	if err := CheckServiceTokens(valid, "Bearer old-secret"); err != nil {
		t.Fatalf("expected an old still-valid token to succeed during rotation, got %v", err)
	}
	if err := CheckServiceTokens(valid, "Bearer new-secret"); err != nil {
		t.Fatalf("expected the new token to succeed, got %v", err)
	}
	if err := CheckServiceTokens(valid, "Bearer wrong"); err == nil {
		t.Fatal("expected a mismatched token to fail")
	}
	if err := CheckServiceTokens(valid, "old-secret"); err == nil {
		t.Fatal("expected a non-Bearer header to fail")
	}
}

func TestParseTokenList(t *testing.T) {
	got := ParseTokenList(" a , ,b,c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("ParseTokenList() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ParseTokenList() = %v, want %v", got, want)
		}
	}
}

func TestGenerateApplianceSecretIsScopedAndUnique(t *testing.T) {
	a, err := GenerateApplianceSecret(5)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateApplianceSecret(5)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two generated secrets for the same appliance should not collide")
	}
}
