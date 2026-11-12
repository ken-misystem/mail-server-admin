-- DESIGN PROPOSAL ONLY. Do not apply before inspecting the live Roundcube DB.
-- Assumes no Roundcube table prefix. Adjust only after read-only verification.

CREATE TABLE `auth_webauthn_users` (
    `user_id` INT(10) UNSIGNED NOT NULL,
    `user_handle` BINARY(32) NOT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`user_id`),
    UNIQUE KEY `auth_webauthn_users_handle_uq` (`user_handle`),
    UNIQUE KEY `auth_webauthn_users_user_handle_uq` (`user_id`, `user_handle`),
    CONSTRAINT `auth_webauthn_users_user_fk`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
        ON DELETE CASCADE
) ROW_FORMAT=DYNAMIC ENGINE=InnoDB
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `auth_webauthn_credentials` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT(10) UNSIGNED NOT NULL,
    `credential_id` VARBINARY(1023) NOT NULL,
    `user_handle` BINARY(32) NOT NULL,
    `credential_record_json` LONGTEXT
        CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `sign_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `transports_json` LONGTEXT
        CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `label` VARCHAR(100) NOT NULL,
    `enabled` TINYINT(1) NOT NULL DEFAULT 1,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `last_used_at` DATETIME NULL,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `auth_webauthn_credentials_id_uq` (`credential_id`),
    KEY `auth_webauthn_credentials_user_enabled_idx` (`user_id`, `enabled`),
    KEY `auth_webauthn_credentials_handle_idx` (`user_handle`),
    CONSTRAINT `auth_webauthn_credentials_user_handle_fk`
        FOREIGN KEY (`user_id`, `user_handle`)
        REFERENCES `auth_webauthn_users` (`user_id`, `user_handle`)
        ON DELETE CASCADE,
    CONSTRAINT `auth_webauthn_credentials_record_json_ck`
        CHECK (JSON_VALID(`credential_record_json`)),
    CONSTRAINT `auth_webauthn_credentials_transports_json_ck`
        CHECK (JSON_VALID(`transports_json`)),
    CONSTRAINT `auth_webauthn_credentials_handle_ck`
        CHECK (OCTET_LENGTH(`user_handle`) = 32),
    CONSTRAINT `auth_webauthn_credentials_id_length_ck`
        CHECK (OCTET_LENGTH(`credential_id`) BETWEEN 1 AND 1023),
    CONSTRAINT `auth_webauthn_credentials_enabled_ck`
        CHECK (`enabled` IN (0, 1))
) ROW_FORMAT=DYNAMIC ENGINE=InnoDB
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
