// Package hostnames allocates the per-Appliance hostname label described in
// the README's "Appliance" model: every appliance is reachable at
// <label>.<base domain> (e.g. *.appliance.humi.kaese.space) once claimed.
package hostnames

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var nonLabelChars = regexp.MustCompile(`[^a-z0-9-]+`)
var collapseDashes = regexp.MustCompile(`-+`)

const maxNamePart = 40
const suffixBytes = 3 // 6 hex chars, keeps collisions rare without a lookup

// GenerateLabel derives a DNS-label-safe hostname label from an appliance
// name plus a random suffix. The suffix is what actually guarantees
// uniqueness is *likely*; the database's UNIQUE constraint on hostnameLabel
// is what guarantees it - callers should retry with a fresh label on a
// duplicate-key error rather than trust this function alone.
func GenerateLabel(name string) (string, error) {
	sanitized := strings.ToLower(strings.TrimSpace(name))
	sanitized = nonLabelChars.ReplaceAllString(sanitized, "-")
	sanitized = collapseDashes.ReplaceAllString(sanitized, "-")
	sanitized = strings.Trim(sanitized, "-")
	if len(sanitized) > maxNamePart {
		sanitized = strings.Trim(sanitized[:maxNamePart], "-")
	}
	if sanitized == "" {
		sanitized = "appliance"
	}

	buf := make([]byte, suffixBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", sanitized, hex.EncodeToString(buf)), nil
}

// FullHostname joins a label with the configured base domain.
func FullHostname(label string, baseDomain string) string {
	return fmt.Sprintf("%s.%s", label, baseDomain)
}
