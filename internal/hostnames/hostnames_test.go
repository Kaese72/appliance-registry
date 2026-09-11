package hostnames

import (
	"regexp"
	"testing"
)

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

func TestGenerateLabelIsDNSSafe(t *testing.T) {
	cases := []string{"My Appliance!", "  leading/trailing -- dashes  ", "", "こんにちは", "UPPER_CASE_123"}
	for _, name := range cases {
		label, err := GenerateLabel(name)
		if err != nil {
			t.Fatalf("GenerateLabel(%q): %v", name, err)
		}
		if !labelRe.MatchString(label) {
			t.Fatalf("GenerateLabel(%q) = %q, not a valid DNS label", name, label)
		}
	}
}

func TestGenerateLabelIsLikelyUnique(t *testing.T) {
	a, err := GenerateLabel("kitchen")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateLabel("kitchen")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two labels generated from the same name should not collide")
	}
}

func TestFullHostname(t *testing.T) {
	got := FullHostname("kitchen-abc123", "appliance.humi.kaese.space")
	want := "kitchen-abc123.appliance.humi.kaese.space"
	if got != want {
		t.Fatalf("FullHostname() = %q, want %q", got, want)
	}
}
