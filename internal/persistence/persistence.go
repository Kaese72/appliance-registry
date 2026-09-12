package persistence

import (
	"context"
	"time"
)

type ApplianceStatus string

const (
	// StatusPending: created via registration, not yet claimed. Has no
	// working cloud-connect credentials.
	StatusPending ApplianceStatus = "pending"
	// StatusActive: claimed, has valid cloud-connect credentials and a
	// cloud-side cloud-connect-server provisioned for it.
	StatusActive ApplianceStatus = "active"
	// StatusRevoked: access withdrawn. Credentials are no longer valid and
	// the hostname is freed for reuse.
	StatusRevoked ApplianceStatus = "revoked"
)

// Appliance represents one physical/local Huemie install - see the
// README's "Appliance" model. GroupID refers to a Group owned by
// cloud-user-registry; this service has no access to that database and
// can't validate the id beyond "well-formed", so authorization on top of
// GroupID is limited to "does the caller's use token carry this group id",
// not "is the caller an admin of it" - see the README's "Architecture"
// section for why.
type Appliance struct {
	ID            int64
	Name          string
	HostnameLabel string
	GroupID       int64
	Status        ApplianceStatus
	CreatedAt     time.Time
	ClaimedAt     *time.Time
	LastSeenAt    *time.Time
}

// ClaimToken is the single-use, appliance-scoped bootstrap credential
// described in the README's "Claim token" model. Only its hash is
// persisted; the raw value is returned once, at issue time, and never
// stored.
type ClaimToken struct {
	ApplianceID int64
	TokenHash   string
	ExpiresAt   time.Time
}

// EnrollExchangeCode is the single-use, browser-facing credential described
// in migrations/V002.sql. ClaimTokenHash pins it to the claim token that
// existed at issuance time - see that migration's comment.
type EnrollExchangeCode struct {
	ApplianceID    int64
	CodeHash       string
	ClaimTokenHash string
	ExpiresAt      time.Time
}

// ApplianceRegistryDB is the full persistence surface this service needs.
// It is intentionally one interface rather than several small ones (unlike
// cloud-user-registry's split) because every handler in this service
// touches both appliances and claim tokens.
type ApplianceRegistryDB interface {
	// CreateAppliance inserts a new pending Appliance. Callers are expected
	// to retry with a different hostnameLabel on a duplicate-label error,
	// since labels are generated with a random suffix specifically to make
	// collisions rare but not impossible.
	CreateAppliance(ctx context.Context, name string, hostnameLabel string, groupID int64) (Appliance, error)
	GetAppliance(ctx context.Context, id int64) (Appliance, error)
	ListAppliancesForGroup(ctx context.Context, groupID int64) ([]Appliance, error)
	ListAppliancesByStatus(ctx context.Context, status ApplianceStatus) ([]Appliance, error)
	SetApplianceStatus(ctx context.Context, id int64, status ApplianceStatus) error
	// MarkApplianceClaimed moves an Appliance from pending to active and
	// stamps claimedAt, in one statement so the two never drift apart.
	MarkApplianceClaimed(ctx context.Context, id int64) error

	// SaveClaimToken replaces any existing claim token for applianceID -
	// re-issuing invalidates whatever token existed before, per the
	// README's "Registration" and "Claiming" sections.
	SaveClaimToken(ctx context.Context, applianceID int64, tokenHash string, expiresAt time.Time) error
	GetClaimToken(ctx context.Context, applianceID int64) (ClaimToken, error)
	DeleteClaimToken(ctx context.Context, applianceID int64) error

	// SaveEnrollExchangeCode replaces any existing exchange code for
	// applianceID, mirroring SaveClaimToken's re-issue-invalidates-prior
	// behavior.
	SaveEnrollExchangeCode(ctx context.Context, applianceID int64, codeHash string, claimTokenHash string, expiresAt time.Time) error
	GetEnrollExchangeCode(ctx context.Context, applianceID int64) (EnrollExchangeCode, error)
	DeleteEnrollExchangeCode(ctx context.Context, applianceID int64) error
}
