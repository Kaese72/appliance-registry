-- Appliances live in a different service/database than the Groups that own
-- them (cloud-user-registry), so groupId is not a foreign key here - see
-- the README's "Architecture" section.
CREATE TABLE IF NOT EXISTS appliances (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    hostnameLabel VARCHAR(255) NOT NULL,
    groupId BIGINT UNSIGNED NOT NULL,
    status ENUM('pending', 'active', 'revoked') NOT NULL DEFAULT 'pending',
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- Set together, by MarkApplianceClaimed, the moment a Claim token is
    -- successfully redeemed.
    claimedAt TIMESTAMP NULL,
    -- Reserved for a future heartbeat mechanism; nothing writes to this yet.
    lastSeenAt TIMESTAMP NULL,
    CONSTRAINT unique_hostname_label UNIQUE (hostnameLabel)
);

CREATE INDEX idx_appliances_group ON appliances (groupId);
CREATE INDEX idx_appliances_status ON appliances (status);

-- The single-use bootstrap credential for the Appliance that hasn't been
-- claimed yet. Only its hash is stored - see the README's "Claim token"
-- model. One row per appliance: re-registering a claim token overwrites
-- (invalidates) any prior one for the same appliance.
CREATE TABLE IF NOT EXISTS applianceClaimTokens (
    applianceId BIGINT UNSIGNED NOT NULL PRIMARY KEY,
    tokenHash CHAR(64) NOT NULL,
    expiresAt TIMESTAMP NOT NULL,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (applianceId) REFERENCES appliances(id) ON DELETE CASCADE
);
