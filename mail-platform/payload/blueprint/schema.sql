CREATE DATABASE mailserver CHARACTER SET utf8mb4;

CREATE DATABASE mail_management CHARACTER SET utf8mb4;

SET FOREIGN_KEY_CHECKS=0;

USE `mailserver`;

CREATE TABLE `account_recovery` (
  `email` varchar(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `recovery_email` varchar(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `verified_at` datetime DEFAULT NULL,
  `pending_email` varchar(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `verify_token_hash` char(64) DEFAULT NULL,
  `verify_expires_at` datetime DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`email`),
  KEY `idx_verify_token` (`verify_token_hash`),
  KEY `idx_recovery_email` (`recovery_email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

USE `mailserver`;

CREATE TABLE `app_passwords` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned NOT NULL,
  `selector` binary(16) NOT NULL,
  `password_hash` varchar(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `label` varchar(100) NOT NULL,
  `created_at` datetime(6) NOT NULL DEFAULT current_timestamp(6),
  `revoked_at` datetime(6) DEFAULT NULL,
  `last_used_at` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `app_passwords_selector_uq` (`selector`),
  KEY `app_passwords_user_revoked_idx` (`user_id`,`revoked_at`),
  CONSTRAINT `app_passwords_user_fk` FOREIGN KEY (`user_id`) REFERENCES `virtual_users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mailserver`;

CREATE TABLE `password_reset_tokens` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `email` varchar(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `token_hash` char(64) NOT NULL,
  `expires_at` datetime NOT NULL,
  `used_at` datetime DEFAULT NULL,
  `requested_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `requested_ip` varchar(45) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_reset_token` (`token_hash`),
  KEY `idx_reset_email_time` (`email`,`requested_at`),
  KEY `idx_reset_expire` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

USE `mailserver`;

CREATE TABLE `virtual_aliases` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `domain_id` int(10) unsigned NOT NULL,
  `source` varchar(320) NOT NULL,
  `destination` varchar(320) NOT NULL,
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_alias` (`source`,`destination`),
  KEY `idx_alias_source` (`source`),
  KEY `idx_alias_domain` (`domain_id`),
  CONSTRAINT `fk_alias_domain` FOREIGN KEY (`domain_id`) REFERENCES `virtual_domains` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mailserver`;

CREATE TABLE `virtual_domains` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_domain_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mailserver`;

CREATE TABLE `virtual_domain_aliases` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `alias_domain` varchar(255) NOT NULL,
  `target_domain_id` int(10) unsigned NOT NULL,
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_alias_domain` (`alias_domain`),
  KEY `idx_target_domain` (`target_domain_id`),
  CONSTRAINT `fk_domain_alias_target` FOREIGN KEY (`target_domain_id`) REFERENCES `virtual_domains` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mailserver`;

CREATE TABLE `virtual_recipient_copies` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `source` varchar(320) NOT NULL,
  `destination` varchar(320) NOT NULL,
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_copy_source` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mailserver`;

CREATE TABLE `virtual_users` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `domain_id` int(10) unsigned NOT NULL,
  `email` varchar(320) NOT NULL,
  `password` varchar(255) NOT NULL,
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `quota_bytes` bigint(20) unsigned NOT NULL DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `auth_epoch` bigint(20) unsigned NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_user_email` (`email`),
  KEY `idx_users_domain` (`domain_id`),
  CONSTRAINT `fk_users_domain` FOREIGN KEY (`domain_id`) REFERENCES `virtual_domains` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_address_preferences` (
  `user_id` bigint(20) unsigned NOT NULL,
  `ignore_dots` tinyint(3) unsigned NOT NULL DEFAULT 0,
  `allow_plus` tinyint(3) unsigned NOT NULL DEFAULT 0,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`user_id`),
  CONSTRAINT `fk_address_preferences_user` FOREIGN KEY (`user_id`) REFERENCES `mailserver`.`virtual_users` (`id`),
  CONSTRAINT `ck_address_preferences_dots` CHECK (`ignore_dots` in (0,1)),
  CONSTRAINT `ck_address_preferences_plus` CHECK (`allow_plus` in (0,1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_admin_audit` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `admin_id` bigint(20) unsigned DEFAULT NULL,
  `action` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `target_type` varchar(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `target_id` varchar(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_mail_admin_audit_time` (`created_at`),
  KEY `fk_mail_admin_audit_actor` (`admin_id`),
  CONSTRAINT `fk_mail_admin_audit_actor` FOREIGN KEY (`admin_id`) REFERENCES `mail_admin_users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_admin_credentials` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `admin_id` bigint(20) unsigned NOT NULL,
  `credential_id` varbinary(1024) NOT NULL,
  `credential_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `label` varchar(128) NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_used_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_mail_admin_credential` (`credential_id`),
  KEY `fk_mail_admin_credential_owner` (`admin_id`),
  CONSTRAINT `fk_mail_admin_credential_owner` FOREIGN KEY (`admin_id`) REFERENCES `mail_admin_users` (`id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (json_valid(`credential_json`)),
  CONSTRAINT `CONSTRAINT_2` CHECK (`enabled` in (0,1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_admin_users` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `email` varchar(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `password_hash` varchar(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `user_handle` varbinary(64) NOT NULL,
  `active` tinyint(1) NOT NULL DEFAULT 0,
  `is_system_admin` tinyint(1) NOT NULL DEFAULT 0,
  `auth_epoch` bigint(20) unsigned NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_mail_admin_email` (`email`),
  UNIQUE KEY `uq_mail_admin_handle` (`user_handle`),
  CONSTRAINT `CONSTRAINT_1` CHECK (`active` in (0,1)),
  CONSTRAINT `CONSTRAINT_2` CHECK (`is_system_admin` in (0,1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_client_devices` (
  `sequence_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `id` binary(16) NOT NULL,
  `owner_id` bigint(20) unsigned NOT NULL,
  `owner_epoch` bigint(20) unsigned NOT NULL,
  `owner_identity_version` bigint(20) unsigned NOT NULL,
  `label` varchar(100) NOT NULL,
  `request_id` binary(16) NOT NULL,
  `request_digest` binary(32) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `state` enum('pending','active','issuance_unknown','failed','revoke_pending','revoked','expired') NOT NULL,
  `certificate_sha256` binary(32) DEFAULT NULL,
  `issuer_id` binary(16) DEFAULT NULL,
  `serial` varbinary(20) DEFAULT NULL,
  `not_before` datetime(6) DEFAULT NULL,
  `expires_at` datetime(6) DEFAULT NULL,
  `revocation_generation` bigint(20) unsigned NOT NULL DEFAULT 0,
  `pending_components` longtext CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `sequence_uq` (`sequence_id`),
  UNIQUE KEY `owner_request_uq` (`owner_id`,`request_id`),
  UNIQUE KEY `device_owner_uq` (`id`,`owner_id`),
  UNIQUE KEY `cert_uq` (`certificate_sha256`),
  UNIQUE KEY `issuer_serial_uq` (`issuer_id`,`serial`),
  KEY `owner_sequence_idx` (`owner_id`,`sequence_id`),
  CONSTRAINT `mail_client_devices_ibfk_1` FOREIGN KEY (`owner_id`) REFERENCES `mail_client_owner_locks` (`owner_id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (json_valid(`pending_components`))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_client_downloads` (
  `device_id` binary(16) NOT NULL,
  `owner_id` bigint(20) unsigned NOT NULL,
  `session_binding_hash` binary(32) NOT NULL,
  `handle_hash` binary(32) NOT NULL,
  `expires_at` datetime(6) NOT NULL,
  `state` enum('ready','consumed','stream_completed','unknown','expired','cancelled') NOT NULL,
  PRIMARY KEY (`device_id`),
  UNIQUE KEY `handle_hash` (`handle_hash`),
  KEY `device_id` (`device_id`,`owner_id`),
  KEY `owner_lifecycle_expiry_v1` (`state`,`expires_at`,`device_id`,`owner_id`),
  CONSTRAINT `mail_client_downloads_ibfk_1` FOREIGN KEY (`device_id`, `owner_id`) REFERENCES `mail_client_devices` (`id`, `owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_client_issuer_journal` (
  `device_id` binary(16) NOT NULL,
  `issuer_id` binary(16) NOT NULL,
  `serial` varbinary(20) NOT NULL,
  `state` enum('reserved','signed','unknown','revoked') NOT NULL,
  `certificate_sha256` binary(32) DEFAULT NULL,
  `not_before` datetime(6) DEFAULT NULL,
  `expires_at` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`device_id`),
  UNIQUE KEY `serial_journal_uq` (`issuer_id`,`serial`),
  CONSTRAINT `mail_client_issuer_journal_ibfk_1` FOREIGN KEY (`device_id`) REFERENCES `mail_client_devices` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_client_owner_locks` (
  `owner_id` bigint(20) unsigned NOT NULL,
  `identity_version` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `canonical_mailbox` varchar(320) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `domain_id` int(10) unsigned NOT NULL,
  `owner_created_at` datetime(6) NOT NULL,
  `domain_created_at` datetime(6) NOT NULL,
  `retired` tinyint(3) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`owner_id`),
  UNIQUE KEY `identity_version` (`identity_version`),
  KEY `cert_domain_live_fk` (`domain_id`),
  CONSTRAINT `cert_domain_live_fk` FOREIGN KEY (`domain_id`) REFERENCES `mailserver`.`virtual_domains` (`id`),
  CONSTRAINT `cert_owner_live_fk` FOREIGN KEY (`owner_id`) REFERENCES `mailserver`.`virtual_users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_client_revocation_acks` (
  `device_id` binary(16) NOT NULL,
  `generation` bigint(20) unsigned NOT NULL,
  `component` enum('imaps','pop3s','submission','resumption','existing_sessions','crl','material_retired') NOT NULL,
  `acknowledged_at` datetime(6) NOT NULL,
  PRIMARY KEY (`device_id`,`generation`,`component`),
  CONSTRAINT `mail_client_revocation_acks_ibfk_1` FOREIGN KEY (`device_id`) REFERENCES `mail_client_devices` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_domain_delivery_policy` (
  `domain_id` int(10) unsigned NOT NULL,
  `follow_mx` tinyint(3) unsigned NOT NULL DEFAULT 0,
  `revision` bigint(20) unsigned NOT NULL DEFAULT 1,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`domain_id`),
  CONSTRAINT `fk_domain_delivery_domain` FOREIGN KEY (`domain_id`) REFERENCES `mailserver`.`virtual_domains` (`id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (`follow_mx` in (0,1)),
  CONSTRAINT `CONSTRAINT_2` CHECK (`revision` > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

USE `mail_management`;

CREATE TABLE `mail_feature_bulk_runs` (
  `request_id` char(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `admin_id` bigint(20) unsigned NOT NULL,
  `row_count` smallint(5) unsigned NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`request_id`),
  KEY `admin_id` (`admin_id`),
  CONSTRAINT `mail_feature_bulk_runs_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `mail_admin_users` (`id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (`row_count` between 1 and 25)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_feature_delegation_runs` (
  `request_id` char(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `actor_id` bigint(20) unsigned NOT NULL,
  `target_admin_id` bigint(20) unsigned NOT NULL,
  `domain_id` int(10) unsigned NOT NULL,
  `request_digest` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `revision` bigint(20) unsigned NOT NULL,
  `before_capabilities` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`before_capabilities`)),
  `after_capabilities` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`after_capabilities`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`request_id`),
  KEY `actor_id` (`actor_id`),
  KEY `target_admin_id` (`target_admin_id`),
  KEY `domain_id` (`domain_id`),
  CONSTRAINT `mail_feature_delegation_runs_ibfk_1` FOREIGN KEY (`actor_id`) REFERENCES `mail_admin_users` (`id`),
  CONSTRAINT `mail_feature_delegation_runs_ibfk_2` FOREIGN KEY (`target_admin_id`) REFERENCES `mail_admin_users` (`id`),
  CONSTRAINT `mail_feature_delegation_runs_ibfk_3` FOREIGN KEY (`domain_id`) REFERENCES `mailserver`.`virtual_domains` (`id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (`revision` > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_feature_domain_grants` (
  `admin_id` bigint(20) unsigned NOT NULL,
  `domain_id` int(10) unsigned NOT NULL,
  `capability` varchar(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `active` tinyint(3) unsigned NOT NULL DEFAULT 1,
  `revision` bigint(20) unsigned NOT NULL DEFAULT 1,
  PRIMARY KEY (`admin_id`,`domain_id`,`capability`),
  KEY `domain_id` (`domain_id`),
  CONSTRAINT `mail_feature_domain_grants_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `mail_admin_users` (`id`),
  CONSTRAINT `mail_feature_domain_grants_ibfk_2` FOREIGN KEY (`domain_id`) REFERENCES `mailserver`.`virtual_domains` (`id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (`active` in (0,1)),
  CONSTRAINT `CONSTRAINT_2` CHECK (`revision` > 0),
  CONSTRAINT `CONSTRAINT_3` CHECK (`capability` in ('mailbox.read','mailbox.create','mailbox.state','mailbox.password','mailbox.quota','alias.read','alias.create','alias.change','forward.read','forward.change','usage.read','csv.preview','csv.apply'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_feature_forwards` (
  `user_id` bigint(20) unsigned NOT NULL,
  `destinations` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`destinations`)),
  `enabled` tinyint(3) unsigned NOT NULL DEFAULT 0,
  `revision` bigint(20) unsigned NOT NULL DEFAULT 1,
  `health_reset_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`user_id`),
  CONSTRAINT `mail_feature_forwards_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `mailserver`.`virtual_users` (`id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (json_type(`destinations`) = 'ARRAY'),
  CONSTRAINT `CONSTRAINT_2` CHECK (json_length(`destinations`) <= 10),
  CONSTRAINT `CONSTRAINT_3` CHECK (`enabled` in (0,1)),
  CONSTRAINT `CONSTRAINT_4` CHECK (`enabled` = 0 or json_length(`destinations`) > 0),
  CONSTRAINT `CONSTRAINT_5` CHECK (`revision` > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_feature_operation_runs` (
  `request_id` char(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `admin_id` bigint(20) unsigned NOT NULL,
  `action` varchar(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `target_id` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`request_id`),
  KEY `admin_id` (`admin_id`),
  CONSTRAINT `mail_feature_operation_runs_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `mail_admin_users` (`id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (`action` in ('mailbox_create','mailbox_state','mailbox_password','mailbox_quota','alias_create','alias_state','alias_destination'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_feature_settings` (
  `kind` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `revision` bigint(20) unsigned NOT NULL,
  `payload` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`payload`)),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`kind`),
  CONSTRAINT `CONSTRAINT_1` CHECK (`kind` in ('access','spam')),
  CONSTRAINT `CONSTRAINT_2` CHECK (`revision` > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_feature_setting_runs` (
  `request_id` char(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `admin_id` bigint(20) unsigned NOT NULL,
  `action` varchar(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `target_id` bigint(20) unsigned NOT NULL,
  `revision` bigint(20) unsigned NOT NULL,
  `before_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`before_json`)),
  `after_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`after_json`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`request_id`),
  KEY `admin_id` (`admin_id`),
  CONSTRAINT `mail_feature_setting_runs_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `mail_admin_users` (`id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (`action` in ('forward_change','rules_change','spam_change','upstream_change','attachment_change')),
  CONSTRAINT `CONSTRAINT_2` CHECK (`revision` > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_legacy_smtp_credentials` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `login_id` varchar(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `user_id` bigint(20) unsigned DEFAULT NULL,
  `password_hash` varchar(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `enabled` tinyint(3) unsigned NOT NULL DEFAULT 0,
  `revision` bigint(20) unsigned NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `sender_address` varchar(254) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_legacy_smtp_login` (`login_id`),
  KEY `ix_legacy_smtp_owner` (`user_id`,`enabled`),
  KEY `ix_legacy_smtp_sender` (`sender_address`,`enabled`),
  CONSTRAINT `fk_legacy_smtp_user` FOREIGN KEY (`user_id`) REFERENCES `mailserver`.`virtual_users` (`id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (`enabled` in (0,1)),
  CONSTRAINT `CONSTRAINT_2` CHECK (`revision` > 0),
  CONSTRAINT `ck_legacy_smtp_sender_mode` CHECK (`user_id` is not null and `sender_address` is null or `user_id` is null and `sender_address` is not null and char_length(`sender_address`) between 3 and 254)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

USE `mail_management`;

CREATE TABLE `mail_management_locks` (
  `name` varchar(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_owned_aliases` (
  `virtual_alias_id` bigint(20) unsigned NOT NULL,
  `user_id` bigint(20) unsigned NOT NULL,
  `domain_id` int(10) unsigned NOT NULL,
  `source` varchar(320) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`virtual_alias_id`),
  UNIQUE KEY `uq_mail_owned_alias_source` (`source`),
  KEY `idx_mail_owned_alias_user` (`user_id`),
  KEY `fk_mail_owned_alias_domain` (`domain_id`),
  CONSTRAINT `fk_mail_owned_alias_domain` FOREIGN KEY (`domain_id`) REFERENCES `mailserver`.`virtual_domains` (`id`),
  CONSTRAINT `fk_mail_owned_alias_owner` FOREIGN KEY (`user_id`) REFERENCES `mailserver`.`virtual_users` (`id`),
  CONSTRAINT `fk_mail_owned_alias_route` FOREIGN KEY (`virtual_alias_id`) REFERENCES `mailserver`.`virtual_aliases` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_pop_accounts` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned NOT NULL,
  `remote_host` varchar(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `remote_port` smallint(5) unsigned NOT NULL DEFAULT 995,
  `remote_username` varchar(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `label` varchar(128) NOT NULL,
  `secret_reference` varchar(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `last_success_at` timestamp NULL DEFAULT NULL,
  `last_result` varchar(32) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_mail_pop_source` (`user_id`,`remote_host`,`remote_port`,`remote_username`),
  CONSTRAINT `fk_mail_pop_owner` FOREIGN KEY (`user_id`) REFERENCES `mailserver`.`virtual_users` (`id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (`enabled` in (0,1)),
  CONSTRAINT `CONSTRAINT_2` CHECK (`remote_port` > 0),
  CONSTRAINT `CONSTRAINT_3` CHECK (`enabled` = 0 or `secret_reference` is not null)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_pop_password_boxes` (
  `reference` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `account_id` bigint(20) unsigned NOT NULL,
  `sealed_password` varbinary(1072) NOT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`reference`),
  UNIQUE KEY `uq_mail_pop_password_account` (`account_id`),
  CONSTRAINT `fk_mail_pop_password_account` FOREIGN KEY (`account_id`) REFERENCES `mail_pop_accounts` (`id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (char_length(`reference`) = 64 and `reference` regexp '^[0-9a-f]{64}$'),
  CONSTRAINT `CONSTRAINT_2` CHECK (octet_length(`sealed_password`) between 49 and 1072)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_pop_providers` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `label` varchar(128) NOT NULL,
  `host` varchar(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `port` smallint(5) unsigned NOT NULL DEFAULT 995,
  `active` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_mail_pop_provider_endpoint` (`host`,`port`),
  CONSTRAINT `CONSTRAINT_1` CHECK (`port` > 0),
  CONSTRAINT `CONSTRAINT_2` CHECK (`active` in (0,1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_pop_run_history` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `account_id` bigint(20) unsigned NOT NULL,
  `started_at` datetime(6) NOT NULL,
  `finished_at` datetime(6) DEFAULT NULL,
  `outcome` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `phase` varchar(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `detail_code` varchar(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `fetched_count` smallint(5) unsigned DEFAULT NULL,
  `native_exit` smallint(5) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_pop_run_account` (`account_id`,`id`),
  CONSTRAINT `fk_pop_run_account` FOREIGN KEY (`account_id`) REFERENCES `mail_pop_accounts` (`id`) ON DELETE CASCADE,
  CONSTRAINT `CONSTRAINT_1` CHECK (`outcome` in ('running','success','no_mail','limit_reached','warning','failed')),
  CONSTRAINT `CONSTRAINT_2` CHECK (`fetched_count` is null or `fetched_count` <= 50),
  CONSTRAINT `CONSTRAINT_3` CHECK (`native_exit` is null or `native_exit` <= 255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_send_limit_history` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `admin_id` bigint(20) unsigned NOT NULL,
  `profile` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `revision` bigint(20) unsigned NOT NULL,
  `before_json` text NOT NULL,
  `after_json` text NOT NULL,
  `reason` varchar(200) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `profile_revision` (`profile`,`revision`),
  KEY `fk_send_limit_actor` (`admin_id`),
  CONSTRAINT `fk_send_limit_actor` FOREIGN KEY (`admin_id`) REFERENCES `mail_admin_users` (`id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (json_valid(`before_json`)),
  CONSTRAINT `CONSTRAINT_2` CHECK (json_valid(`after_json`))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

USE `mail_management`;

CREATE TABLE `mail_send_limit_profiles` (
  `profile` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `minute_messages` int(10) unsigned NOT NULL,
  `minute_recipients` int(10) unsigned NOT NULL,
  `hour_messages` int(10) unsigned NOT NULL,
  `hour_recipients` int(10) unsigned NOT NULL,
  `revision` bigint(20) unsigned NOT NULL DEFAULT 1,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`profile`),
  CONSTRAINT `CONSTRAINT_1` CHECK (`profile` in ('mailbox','legacy')),
  CONSTRAINT `CONSTRAINT_2` CHECK (`minute_messages` between 1 and 1000000),
  CONSTRAINT `CONSTRAINT_3` CHECK (`minute_recipients` between `minute_messages` and 1000000),
  CONSTRAINT `CONSTRAINT_4` CHECK (`hour_messages` between `minute_messages` and 1000000),
  CONSTRAINT `CONSTRAINT_5` CHECK (`hour_recipients` between `hour_messages` and 1000000),
  CONSTRAINT `CONSTRAINT_6` CHECK (`hour_recipients` >= `minute_recipients`),
  CONSTRAINT `CONSTRAINT_7` CHECK (`revision` >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE TABLE `mail_user_settings` (
  `user_id` bigint(20) unsigned NOT NULL,
  `alias_limit` int(10) unsigned NOT NULL DEFAULT 0,
  `pop_account_limit` int(10) unsigned NOT NULL DEFAULT 0,
  `pop_poll_seconds` int(10) unsigned NOT NULL DEFAULT 300,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`user_id`),
  CONSTRAINT `fk_mail_user_settings_owner` FOREIGN KEY (`user_id`) REFERENCES `mailserver`.`virtual_users` (`id`),
  CONSTRAINT `CONSTRAINT_1` CHECK (`pop_poll_seconds` between 60 and 86400)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

USE `mail_management`;

CREATE ALGORITHM=MERGE DEFINER=`mailcert_views_v1`@`localhost` SQL SECURITY DEFINER VIEW `mail_management`.`mail_client_bootstrap_current_owners` AS select `u`.`id` AS `owner_id`,`u`.`auth_epoch` AS `auth_epoch`,0 AS `identity_version`,lcase(`u`.`email`) AS `canonical_mailbox`,`u`.`active` = 1 and `d`.`active` = 1 AS `active` from (`mailserver`.`virtual_users` `u` join `mailserver`.`virtual_domains` `d` on(`d`.`id` = `u`.`domain_id`));

USE `mail_management`;

CREATE ALGORITHM=TEMPTABLE DEFINER=`mailcert_views_v1`@`localhost` SQL SECURITY DEFINER VIEW `mail_management`.`mail_client_bootstrap_login_owners` AS select lcase(`u`.`email`) AS `login_name`,`u`.`id` AS `owner_id`,`o`.`active` AS `active` from (`mailserver`.`virtual_users` `u` join `mail_management`.`mail_client_bootstrap_current_owners` `o` on(`o`.`owner_id` = `u`.`id`)) where !exists(select 1 from `mailserver`.`virtual_aliases` `v` where cast(lcase(`v`.`source`) as char charset binary) = cast(lcase(`u`.`email`) as char charset binary) and `v`.`active` = 1 limit 1) union all select concat(substring_index(lcase(`u`.`email`),'@',1),'@',lcase(`a`.`alias_domain`)) AS `Name_exp_1`,`u`.`id` AS `id`,`o`.`active` AS `active` from (((`mailserver`.`virtual_users` `u` join `mailserver`.`virtual_domains` `d` on(`d`.`id` = `u`.`domain_id`)) join `mailserver`.`virtual_domain_aliases` `a` on(`a`.`target_domain_id` = `d`.`id` and `a`.`active` = 1)) join `mail_management`.`mail_client_bootstrap_current_owners` `o` on(`o`.`owner_id` = `u`.`id`)) where cast(lcase(`u`.`email`) as char charset binary) = cast(concat(substring_index(lcase(`u`.`email`),'@',1),'@',lcase(`d`.`name`)) as char charset binary) and !exists(select 1 from `mailserver`.`virtual_aliases` `v` where `v`.`active` = 1 and cast(lcase(`v`.`source`) as char charset binary) = cast(concat(substring_index(lcase(`u`.`email`),'@',1),'@',lcase(`a`.`alias_domain`)) as char charset binary) limit 1);

USE `mail_management`;

CREATE ALGORITHM=MERGE DEFINER=`mailcert_views_v1`@`localhost` SQL SECURITY DEFINER VIEW `mail_management`.`mail_client_current_owners` AS select `u`.`id` AS `owner_id`,`u`.`auth_epoch` AS `auth_epoch`,`l`.`identity_version` AS `identity_version`,`l`.`canonical_mailbox` AS `canonical_mailbox`,`u`.`active` = 1 and `d`.`active` = 1 and `l`.`retired` = 0 and cast(lcase(`u`.`email`) as char charset binary) = cast(`l`.`canonical_mailbox` as char charset binary) and `u`.`domain_id` = `l`.`domain_id` and `u`.`created_at` = `l`.`owner_created_at` and `d`.`created_at` = `l`.`domain_created_at` AS `active` from ((`mailserver`.`virtual_users` `u` join `mailserver`.`virtual_domains` `d` on(`d`.`id` = `u`.`domain_id`)) join `mail_management`.`mail_client_owner_locks` `l` on(`l`.`owner_id` = `u`.`id`));

USE `mail_management`;

CREATE ALGORITHM=TEMPTABLE DEFINER=`mailcert_views_v1`@`localhost` SQL SECURITY DEFINER VIEW `mail_management`.`mail_client_login_owners` AS select lcase(`u`.`email`) AS `login_name`,`u`.`id` AS `owner_id`,`o`.`active` AS `active` from (`mailserver`.`virtual_users` `u` join `mail_management`.`mail_client_current_owners` `o` on(`o`.`owner_id` = `u`.`id`)) where !exists(select 1 from `mailserver`.`virtual_aliases` `v` where cast(lcase(`v`.`source`) as char charset binary) = cast(lcase(`u`.`email`) as char charset binary) and `v`.`active` = 1 limit 1) union all select concat(substring_index(lcase(`u`.`email`),'@',1),'@',lcase(`a`.`alias_domain`)) AS `Name_exp_1`,`u`.`id` AS `id`,`o`.`active` AS `active` from (((`mailserver`.`virtual_users` `u` join `mailserver`.`virtual_domains` `d` on(`d`.`id` = `u`.`domain_id`)) join `mailserver`.`virtual_domain_aliases` `a` on(`a`.`target_domain_id` = `d`.`id` and `a`.`active` = 1)) join `mail_management`.`mail_client_current_owners` `o` on(`o`.`owner_id` = `u`.`id`)) where cast(lcase(`u`.`email`) as char charset binary) = cast(concat(substring_index(lcase(`u`.`email`),'@',1),'@',lcase(`d`.`name`)) as char charset binary) and !exists(select 1 from `mailserver`.`virtual_aliases` `v` where `v`.`active` = 1 and cast(lcase(`v`.`source`) as char charset binary) = cast(concat(substring_index(lcase(`u`.`email`),'@',1),'@',lcase(`a`.`alias_domain`)) as char charset binary) limit 1);

SET FOREIGN_KEY_CHECKS=1;
