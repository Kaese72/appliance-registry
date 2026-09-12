-- The single-use exchange code handed to a browser mid-enrollment (see the
-- README's "Enrollment" section). Unlike a claim token, this is never seen
-- by the appliance's owner directly - it's redeemed server-to-server by the
-- appliance itself, in exchange for the same appliance secret Claim would
-- otherwise hand out. Only its hash is stored. claimTokenHash pins the code
-- to the specific claim token that existed when the code was issued, so a
-- code can't outlive (or be redeemed after) that claim token being replaced,
-- e.g. by a second enroll attempt for the same appliance.
CREATE TABLE IF NOT EXISTS applianceEnrollExchangeCodes (
    applianceId BIGINT UNSIGNED NOT NULL PRIMARY KEY,
    codeHash CHAR(64) NOT NULL,
    claimTokenHash CHAR(64) NOT NULL,
    expiresAt TIMESTAMP NOT NULL,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (applianceId) REFERENCES appliances(id) ON DELETE CASCADE
);
