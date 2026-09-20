package tokens

import "testing"

func TestHashApplianceSecretIsStableAndDistinct(t *testing.T) {
	a, err := GenerateApplianceSecret(1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateApplianceSecret(1)
	if err != nil {
		t.Fatal(err)
	}
	if HashApplianceSecret(a) != HashApplianceSecret(a) {
		t.Error("hash of the same secret must be stable")
	}
	if HashApplianceSecret(a) == HashApplianceSecret(b) {
		t.Error("different secrets must hash differently")
	}
	if len(HashApplianceSecret(a)) != 64 {
		t.Errorf("hash must fit CHAR(64), got %d chars", len(HashApplianceSecret(a)))
	}
}

func TestApplianceSecretFromAuthHeader(t *testing.T) {
	got, err := ApplianceSecretFromAuthHeader("Bearer appliance-1:abc")
	if err != nil || got != "appliance-1:abc" {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := ApplianceSecretFromAuthHeader("appliance-1:abc"); err == nil {
		t.Error("expected error for a header without the Bearer prefix")
	}
}
