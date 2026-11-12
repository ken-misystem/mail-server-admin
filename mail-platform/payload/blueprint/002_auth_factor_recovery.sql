-- DESIGN PROPOSAL ONLY. Do not apply without a fixed, approved migration gate.
-- Plaintext Recovery Codes must never be inserted into this table.

CREATE TABLE `auth_mfa_policy` (
    `user_id` INT(10) UNSIGNED NOT NULL,
    `required` TINYINT(1) NOT NULL DEFAULT 0,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`user_id`),
    CONSTRAINT `auth_mfa_policy_user_fk`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
        ON DELETE CASCADE,
    CONSTRAINT `auth_mfa_policy_required_ck`
        CHECK (`required` IN (0, 1))
) ROW_FORMAT=DYNAMIC ENGINE=InnoDB
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `auth_recovery_codes` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT(10) UNSIGNED NOT NULL,
    `selector` BINARY(16) NOT NULL,
    `code_hash` VARCHAR(255)
        CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `used_at` DATETIME NULL,
    `revoked_at` DATETIME NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `auth_recovery_codes_selector_uq` (`selector`),
    KEY `auth_recovery_codes_user_state_idx`
        (`user_id`, `used_at`, `revoked_at`),
    CONSTRAINT `auth_recovery_codes_user_fk`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
        ON DELETE CASCADE,
    CONSTRAINT `auth_recovery_codes_selector_ck`
        CHECK (OCTET_LENGTH(`selector`) = 16)
) ROW_FORMAT=DYNAMIC ENGINE=InnoDB
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `auth_recovery_rate_limits` (
    `user_id` INT(10) UNSIGNED NOT NULL,
    `window_started_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `failed_attempts` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `blocked_until` DATETIME NULL,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`user_id`),
    KEY `auth_recovery_rate_limits_blocked_idx` (`blocked_until`),
    CONSTRAINT `auth_recovery_rate_limits_user_fk`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
        ON DELETE CASCADE
) ROW_FORMAT=DYNAMIC ENGINE=InnoDB
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
