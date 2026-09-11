package mariadb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Kaese72/appliance-registry/internal/config"
	"github.com/Kaese72/appliance-registry/internal/logging"
	"github.com/Kaese72/appliance-registry/internal/persistence"
	"go.elastic.co/apm/module/apmsql"
)

var _ persistence.ApplianceRegistryDB = mariadbPersistence{}

type mariadbPersistence struct {
	db *sql.DB
}

func NewMariadbPersistence(conf config.DatabaseConfig) (mariadbPersistence, error) {
	db, err := apmsql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC", conf.User, conf.Password, conf.Host, conf.Port, conf.Database))
	if err != nil {
		logging.Fatal(err.Error(), context.Background())
		return mariadbPersistence{}, err
	}
	return mariadbPersistence{db: db}, nil
}

func scanAppliance(row interface{ Scan(...interface{}) error }) (persistence.Appliance, error) {
	var a persistence.Appliance
	var status string
	var claimedAt, lastSeenAt sql.NullTime
	if err := row.Scan(&a.ID, &a.Name, &a.HostnameLabel, &a.GroupID, &status, &a.CreatedAt, &claimedAt, &lastSeenAt); err != nil {
		return persistence.Appliance{}, err
	}
	a.Status = persistence.ApplianceStatus(status)
	if claimedAt.Valid {
		a.ClaimedAt = &claimedAt.Time
	}
	if lastSeenAt.Valid {
		a.LastSeenAt = &lastSeenAt.Time
	}
	return a, nil
}

const applianceColumns = `id, name, hostnameLabel, groupId, status, createdAt, claimedAt, lastSeenAt`

func (m mariadbPersistence) CreateAppliance(ctx context.Context, name string, hostnameLabel string, groupID int64) (persistence.Appliance, error) {
	result, err := m.db.ExecContext(ctx, `INSERT INTO appliances (name, hostnameLabel, groupId, status) VALUES (?, ?, ?, ?)`, name, hostnameLabel, groupID, persistence.StatusPending)
	if err != nil {
		return persistence.Appliance{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return persistence.Appliance{}, err
	}
	return m.GetAppliance(ctx, id)
}

func (m mariadbPersistence) GetAppliance(ctx context.Context, id int64) (persistence.Appliance, error) {
	row := m.db.QueryRowContext(ctx, `SELECT `+applianceColumns+` FROM appliances WHERE id = ?`, id)
	return scanAppliance(row)
}

func (m mariadbPersistence) ListAppliancesForGroup(ctx context.Context, groupID int64) ([]persistence.Appliance, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT `+applianceColumns+` FROM appliances WHERE groupId = ? ORDER BY createdAt ASC`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	appliances := []persistence.Appliance{}
	for rows.Next() {
		a, err := scanAppliance(rows)
		if err != nil {
			return nil, err
		}
		appliances = append(appliances, a)
	}
	return appliances, rows.Err()
}

func (m mariadbPersistence) ListAppliancesByStatus(ctx context.Context, status persistence.ApplianceStatus) ([]persistence.Appliance, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT `+applianceColumns+` FROM appliances WHERE status = ? ORDER BY id ASC`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	appliances := []persistence.Appliance{}
	for rows.Next() {
		a, err := scanAppliance(rows)
		if err != nil {
			return nil, err
		}
		appliances = append(appliances, a)
	}
	return appliances, rows.Err()
}

func (m mariadbPersistence) SetApplianceStatus(ctx context.Context, id int64, status persistence.ApplianceStatus) error {
	result, err := m.db.ExecContext(ctx, `UPDATE appliances SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (m mariadbPersistence) MarkApplianceClaimed(ctx context.Context, id int64) error {
	result, err := m.db.ExecContext(ctx, `UPDATE appliances SET status = ?, claimedAt = CURRENT_TIMESTAMP WHERE id = ?`, persistence.StatusActive, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (m mariadbPersistence) SaveClaimToken(ctx context.Context, applianceID int64, tokenHash string, expiresAt time.Time) error {
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO applianceClaimTokens (applianceId, tokenHash, expiresAt) VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE tokenHash = VALUES(tokenHash), expiresAt = VALUES(expiresAt), createdAt = CURRENT_TIMESTAMP`,
		applianceID, tokenHash, expiresAt)
	return err
}

func (m mariadbPersistence) GetClaimToken(ctx context.Context, applianceID int64) (persistence.ClaimToken, error) {
	row := m.db.QueryRowContext(ctx, `SELECT applianceId, tokenHash, expiresAt FROM applianceClaimTokens WHERE applianceId = ?`, applianceID)
	var ct persistence.ClaimToken
	if err := row.Scan(&ct.ApplianceID, &ct.TokenHash, &ct.ExpiresAt); err != nil {
		return persistence.ClaimToken{}, err
	}
	return ct, nil
}

func (m mariadbPersistence) DeleteClaimToken(ctx context.Context, applianceID int64) error {
	_, err := m.db.ExecContext(ctx, `DELETE FROM applianceClaimTokens WHERE applianceId = ?`, applianceID)
	return err
}
