-- DESIGN PROPOSAL ONLY. Do not apply without a fixed, approved migration gate.
-- Plaintext recovery tokens must never be inserted into these tables.

CREATE TABLE `auth_factor_recovery_tokens` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT(10) UNSIGNED NOT NULL,
    `selector` BINARY(16) NOT NULL,
    `token_hash` VARCHAR(255)
        CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `issued_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `activated_at` DATETIME NULL,
    `claimed_at` DATETIME NULL,
    `claim_nonce_hash` BINARY(32) NULL,
    `expires_at` DATETIME NOT NULL,
    `used_at` DATETIME NULL,
    `revoked_at` DATETIME NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `auth_factor_recovery_tokens_selector_uq` (`selector`),
    KEY `auth_factor_recovery_tokens_user_state_idx`
        (`user_id`, `claimed_at`, `used_at`, `revoked_at`, `expires_at`),
    CONSTRAINT `auth_factor_recovery_tokens_user_fk`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
        ON DELETE CASCADE,
    CONSTRAINT `auth_factor_recovery_tokens_selector_ck`
        CHECK (OCTET_LENGTH(`selector`) = 16),
    CONSTRAINT `auth_factor_recovery_tokens_expiry_ck`
        CHECK (`expires_at` > `issued_at`),
    CONSTRAINT `auth_factor_recovery_tokens_activation_ck`
        CHECK (`activated_at` IS NULL OR
            (`activated_at` >= `issued_at` AND `activated_at` < `expires_at`)),
    CONSTRAINT `auth_factor_recovery_tokens_used_ck`
        CHECK (`used_at` IS NULL OR
            (`claimed_at` IS NOT NULL AND `used_at` >= `claimed_at`)),
    CONSTRAINT `auth_factor_recovery_tokens_claim_ck`
        CHECK ((`claimed_at` IS NULL AND `claim_nonce_hash` IS NULL) OR
            (`claimed_at` IS NOT NULL AND `claim_nonce_hash` IS NOT NULL AND
             `activated_at` IS NOT NULL AND `claimed_at` >= `activated_at` AND
             `claimed_at` < `expires_at`)),
    CONSTRAINT `auth_factor_recovery_tokens_revoked_ck`
        CHECK (`revoked_at` IS NULL OR `revoked_at` >= `issued_at`),
    CONSTRAINT `auth_factor_recovery_tokens_terminal_ck`
        CHECK (`used_at` IS NULL OR `revoked_at` IS NULL)
) ROW_FORMAT=DYNAMIC ENGINE=InnoDB
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `auth_factor_recovery_rate_limits` (
    `user_id` INT(10) UNSIGNED NOT NULL,
    `window_started_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `failed_attempts` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `blocked_until` DATETIME NULL,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`user_id`),
    KEY `auth_factor_recovery_rate_limits_blocked_idx` (`blocked_until`),
    CONSTRAINT `auth_factor_recovery_rate_limits_user_fk`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
        ON DELETE CASCADE,
    CONSTRAINT `auth_factor_recovery_rate_limits_failures_ck`
        CHECK (`failed_attempts` <= 5)
) ROW_FORMAT=DYNAMIC ENGINE=InnoDB
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
