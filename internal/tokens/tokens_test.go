package tokens

import "testing"

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
