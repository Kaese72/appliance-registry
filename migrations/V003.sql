-- Hash of the appliance secret (see the README's "Appliance secret" model),
-- so the appliance can authenticate itself to this service - e.g. to redeem
-- cloud-login codes and re-check a cloud user's access. The raw secret still
-- only lives in the cloud-connect-secret-<id> k8s Secret and on the
-- appliance. NULL until the appliance is next claimed or has its secret
-- rotated; appliances enrolled before this migration must rotate once.
ALTER TABLE appliances ADD COLUMN secretHash CHAR(64) NULL;

-- The single-use exchange code handed to a browser when a cloud user logs in
-- to an appliance (see the README's "Cloud login" section). Unlike
-- applianceEnrollExchangeCodes there can be several outstanding at once for
-- one appliance (several users logging in), so it is keyed by the code hash.
-- The code proves "this cloud user, holding a use token for the appliance's
-- owning group, asked to log in"; only the appliance, presenting its secret,
-- can redeem it. Only its hash is stored.
CREATE TABLE IF NOT EXISTS applianceLoginCodes (
    codeHash CHAR(64) NOT NULL PRIMARY KEY,
    applianceId BIGINT UNSIGNED NOT NULL,
    userId BIGINT UNSIGNED NOT NULL,
    expiresAt TIMESTAMP NOT NULL,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (applianceId) REFERENCES appliances(id) ON DELETE CASCADE
);
