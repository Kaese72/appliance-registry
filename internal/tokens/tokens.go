// Package tokens implements the authentication mechanisms this service
// uses - see the README's "Architecture" section:
//
//   - use tokens: RS256 JWTs issued by cloud-user-registry. Their format is
//     owned by that service's public cloudtoken package, which this service
//     imports to verify them (see cloudtoken.FromAuthHeader); nothing here
//     parses or issues one.
//   - claim tokens: single-use, appliance-scoped bootstrap secrets this
//     service generates and hands out exactly once at registration time.
//   - service tokens: static shared secrets for machine callers. There are
//     two independent, separately-configured sets - one for the generic
//     ListAppliances service-caller path, one for the ArgoCD ApplicationSet
//     Plugin generator specifically, since the latter is reachable over the
//     public internet and a leak of one shouldn't compromise the other.
//     Each set can hold more than one valid value at once, so a token can
//     be rotated by adding the new value everywhere it's checked, then
//     removing the old one once every caller has switched - no instant,
//     synchronized cutover required across services.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

func bearerToken(authHeader string) (string, error) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("missing bearer token")
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer ")), nil
}

// GenerateClaimToken returns a fresh random claim token and the hash that
// should be persisted for it. The raw value is only ever returned here, to
// the caller of the registration endpoint - see the README's "Claim token"
// model on why nothing else is ever stored.
func GenerateClaimToken() (raw string, hash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = hex.EncodeToString(buf)
	return raw, HashClaimToken(raw), nil
}

func HashClaimToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ClaimTokenFromAuthHeader extracts the raw bearer claim token from an
// "Authorization" header value, ready to be hashed and compared against a
// stored ClaimToken.
func ClaimTokenFromAuthHeader(authHeader string) (string, error) {
	return bearerToken(authHeader)
}

// GenerateExchangeCode returns a fresh random enrollment exchange code and
// the hash that should be persisted for it - the same shape as a claim
// token (see GenerateClaimToken), but handed to the browser instead of the
// appliance, and redeemed exactly once at
// POST /appliances/{id}/enroll/redeem.
func GenerateExchangeCode() (raw string, hash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = hex.EncodeToString(buf)
	return raw, HashExchangeCode(raw), nil
}

func HashExchangeCode(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ParseTokenList splits a comma-separated config value into the set of
// currently-valid tokens, trimming whitespace and dropping empty entries.
// Supporting more than one valid value at a time is what lets a token be
// rotated without a single synchronized cutover - see the package doc.
func ParseTokenList(raw string) []string {
	var out []string
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// CheckServiceTokens compares a bearer "Authorization" header value against
// every currently-valid token in constant time each, succeeding if any one
// matches.
func CheckServiceTokens(validTokens []string, authHeader string) error {
	provided, err := bearerToken(authHeader)
	if err != nil {
		return err
	}
	for _, configured := range validTokens {
		if subtle.ConstantTimeCompare([]byte(provided), []byte(configured)) == 1 {
			return nil
		}
	}
	return errors.New("invalid service token")
}

// GenerateApplianceSecret returns a fresh random cloud-connect shared
// secret ("auth" value, in chisel's "user:pass" shape) for an appliance -
// see the README's "Appliance secret" model.
func GenerateApplianceSecret(applianceID int64) (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("appliance-%d:%s", applianceID, hex.EncodeToString(buf)), nil
}
