
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
DROP TABLE IF EXISTS `api_keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `api_keys` (
  `id` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `name` varchar(256) NOT NULL DEFAULT '',
  `key_group` varchar(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
  `allowed_pools` json DEFAULT NULL,
  `labels` json NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `generation_hash` varchar(128) NOT NULL DEFAULT '',
  `created_at` bigint unsigned NOT NULL,
  `updated_at` bigint unsigned NOT NULL,
  `expires_at` bigint unsigned DEFAULT NULL,
  `deleted_at` bigint unsigned DEFAULT NULL,
  `revision` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `idx_api_keys_revision` (`revision`),
  KEY `idx_api_keys_group` (`key_group`),
  CONSTRAINT `ck_api_keys_expiry` CHECK (((`expires_at` is null) or (`expires_at` > `created_at`))),
  CONSTRAINT `ck_api_keys_labels_json` CHECK (json_valid(`labels`)),
  CONSTRAINT `ck_api_keys_pools_json` CHECK (((`allowed_pools` is null) or json_valid(`allowed_pools`))),
  CONSTRAINT `ck_api_keys_tombstone` CHECK (((`deleted_at` is null) or (`enabled` = false)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `api_keys` WRITE;
/*!40000 ALTER TABLE `api_keys` DISABLE KEYS */;
INSERT INTO `api_keys` (`id`, `name`, `key_group`, `allowed_pools`, `labels`, `enabled`, `generation_hash`, `created_at`, `updated_at`, `expires_at`, `deleted_at`, `revision`) VALUES ('vk_55cb1808aabb09e6e14e517d91ce0c13','fixture-grouped','fixture',NULL,'{}',1,'binding:vk_55cb1808aabb09e6e14e517d91ce0c13:be7e38dbe55cd386d05aaf4e2dcdacb1',1791956529,1791956529,NULL,NULL,1);
INSERT INTO `api_keys` (`id`, `name`, `key_group`, `allowed_pools`, `labels`, `enabled`, `generation_hash`, `created_at`, `updated_at`, `expires_at`, `deleted_at`, `revision`) VALUES ('vk_c178b4fe1d02f68e5583171e0dc5b7c2','fixture-ungrouped','',NULL,'{}',1,'binding:vk_c178b4fe1d02f68e5583171e0dc5b7c2:b510e86e5d5517abfe6934295746ba8e',1791956529,1791956529,NULL,NULL,2);
/*!40000 ALTER TABLE `api_keys` ENABLE KEYS */;
UNLOCK TABLES;
DROP TABLE IF EXISTS `audit_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `audit_log` (
  `seq` bigint NOT NULL,
  `ts` bigint unsigned NOT NULL,
  `action` varchar(64) NOT NULL,
  `resource` varchar(255) NOT NULL DEFAULT '',
  `outcome` varchar(32) NOT NULL,
  `principal` varchar(255) NOT NULL DEFAULT '',
  `prev_hash` char(64) NOT NULL DEFAULT '',
  `hash` char(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`seq`),
  KEY `idx_audit_resource_seq` (`resource`,`seq`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `audit_log` WRITE;
/*!40000 ALTER TABLE `audit_log` DISABLE KEYS */;
INSERT INTO `audit_log` (`seq`, `ts`, `action`, `resource`, `outcome`, `principal`, `prev_hash`, `hash`) VALUES (1,1791956529,'key.create','key:vk_55cb1808aabb09e6e14e517d91ce0c13','applied','admin','','943e589374a96ca67f363de09c6ecc81e202dd2be8b2f233bf73d80b2ccf757a');
INSERT INTO `audit_log` (`seq`, `ts`, `action`, `resource`, `outcome`, `principal`, `prev_hash`, `hash`) VALUES (2,1791956529,'key.create','key:vk_c178b4fe1d02f68e5583171e0dc5b7c2','applied','admin','943e589374a96ca67f363de09c6ecc81e202dd2be8b2f233bf73d80b2ccf757a','ba8b217909a2587b7b2ddf5df6f712bc49c472f9c0b8a7b9189856b4a68d7424');
/*!40000 ALTER TABLE `audit_log` ENABLE KEYS */;
UNLOCK TABLES;
DROP TABLE IF EXISTS `credentials`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `credentials` (
  `id` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `key_id` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `kind` varchar(32) NOT NULL,
  `slot` tinyint NOT NULL,
  `public_id` varchar(256) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `secret` text,
  `secret_form` varchar(16) NOT NULL,
  `created_at` bigint unsigned NOT NULL,
  `updated_at` bigint unsigned NOT NULL,
  `expires_at` bigint unsigned DEFAULT NULL,
  `revoked_at` bigint unsigned DEFAULT NULL,
  `revoke_reason` varchar(512) DEFAULT NULL,
  `revision` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_cred_public` (`kind`,`public_id`),
  UNIQUE KEY `uq_cred_slot` (`key_id`,`kind`,`slot`),
  KEY `idx_cred_revision` (`revision`),
  CONSTRAINT `fk_cred_key` FOREIGN KEY (`key_id`) REFERENCES `api_keys` (`id`) ON DELETE CASCADE,
  CONSTRAINT `ck_cred_form` CHECK ((`secret_form` in (_utf8mb4'none',_utf8mb4'recoverable',_utf8mb4'digest'))),
  CONSTRAINT `ck_cred_form_null` CHECK (((`secret_form` = _utf8mb4'none') = (`secret` is null))),
  CONSTRAINT `ck_cred_kind` CHECK ((`kind` = _utf8mb4'sigv4')),
  CONSTRAINT `ck_cred_sigv4_recov` CHECK (((`kind` <> _utf8mb4'sigv4') or (`secret_form` = _utf8mb4'recoverable'))),
  CONSTRAINT `ck_cred_slot` CHECK ((`slot` in (0,1)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `credentials` WRITE;
/*!40000 ALTER TABLE `credentials` DISABLE KEYS */;
/*!40000 ALTER TABLE `credentials` ENABLE KEYS */;
UNLOCK TABLES;
DROP TABLE IF EXISTS `denylist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `denylist` (
  `sub` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `reason` varchar(512) NOT NULL DEFAULT '',
  `revoked_at` bigint unsigned NOT NULL,
  `expires_at` bigint unsigned NOT NULL,
  `revoked_generation` varchar(128) DEFAULT NULL,
  `revision` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`sub`),
  KEY `idx_denylist_revision` (`revision`),
  KEY `idx_denylist_expires` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `denylist` WRITE;
/*!40000 ALTER TABLE `denylist` DISABLE KEYS */;
/*!40000 ALTER TABLE `denylist` ENABLE KEYS */;
UNLOCK TABLES;
DROP TABLE IF EXISTS `store_meta`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `store_meta` (
  `k` varchar(191) NOT NULL,
  `v` text NOT NULL,
  PRIMARY KEY (`k`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `store_meta` WRITE;
/*!40000 ALTER TABLE `store_meta` DISABLE KEYS */;
INSERT INTO `store_meta` (`k`, `v`) VALUES ('schema_version','3');
/*!40000 ALTER TABLE `store_meta` ENABLE KEYS */;
UNLOCK TABLES;
DROP TABLE IF EXISTS `store_sequence`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `store_sequence` (
  `id` int NOT NULL,
  `revision` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  CONSTRAINT `ck_seq_singleton` CHECK ((`id` = 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `store_sequence` WRITE;
/*!40000 ALTER TABLE `store_sequence` DISABLE KEYS */;
INSERT INTO `store_sequence` (`id`, `revision`) VALUES (1,2);
/*!40000 ALTER TABLE `store_sequence` ENABLE KEYS */;
UNLOCK TABLES;
DROP TABLE IF EXISTS `usage_metering`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `usage_metering` (
  `bucket` char(10) NOT NULL,
  `key_id` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `provider` varchar(128) NOT NULL,
  `model` varchar(256) NOT NULL,
  `key_group_at_use` varchar(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
  `pricing_version` varchar(64) NOT NULL DEFAULT '',
  `requests` bigint unsigned NOT NULL DEFAULT '0',
  `billable_requests` bigint unsigned NOT NULL DEFAULT '0',
  `tokens_input` bigint unsigned NOT NULL DEFAULT '0',
  `tokens_output` bigint unsigned NOT NULL DEFAULT '0',
  `tokens_cache_read` bigint unsigned NOT NULL DEFAULT '0',
  `tokens_cache_write` bigint unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`key_id`,`bucket`,`model`,`provider`),
  KEY `idx_metering_bucket` (`bucket`),
  CONSTRAINT `fk_metering_key` FOREIGN KEY (`key_id`) REFERENCES `api_keys` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `usage_metering` WRITE;
/*!40000 ALTER TABLE `usage_metering` DISABLE KEYS */;
INSERT INTO `usage_metering` (`bucket`, `key_id`, `provider`, `model`, `key_group_at_use`, `pricing_version`, `requests`, `billable_requests`, `tokens_input`, `tokens_output`, `tokens_cache_read`, `tokens_cache_write`) VALUES ('1791936000','vk_55cb1808aabb09e6e14e517d91ce0c13','fixture-openai','m-cache','','',1,1,7,7,4,0);
INSERT INTO `usage_metering` (`bucket`, `key_id`, `provider`, `model`, `key_group_at_use`, `pricing_version`, `requests`, `billable_requests`, `tokens_input`, `tokens_output`, `tokens_cache_read`, `tokens_cache_write`) VALUES ('1791936000','vk_55cb1808aabb09e6e14e517d91ce0c13','fixture-openai','m-chat','','',2,2,22,14,0,0);
INSERT INTO `usage_metering` (`bucket`, `key_id`, `provider`, `model`, `key_group_at_use`, `pricing_version`, `requests`, `billable_requests`, `tokens_input`, `tokens_output`, `tokens_cache_read`, `tokens_cache_write`) VALUES ('1791936000','vk_c178b4fe1d02f68e5583171e0dc5b7c2','fixture-openai','m-cache','','',1,1,7,7,4,0);
INSERT INTO `usage_metering` (`bucket`, `key_id`, `provider`, `model`, `key_group_at_use`, `pricing_version`, `requests`, `billable_requests`, `tokens_input`, `tokens_output`, `tokens_cache_read`, `tokens_cache_write`) VALUES ('1791936000','vk_c178b4fe1d02f68e5583171e0dc5b7c2','fixture-openai','m-chat','','',1,1,11,7,0,0);
/*!40000 ALTER TABLE `usage_metering` ENABLE KEYS */;
UNLOCK TABLES;
DROP TABLE IF EXISTS `usage_windows`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `usage_windows` (
  `window_start` bigint unsigned NOT NULL,
  `bucket_scope` varchar(8) NOT NULL,
  `bucket_id` varchar(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `model` varchar(256) NOT NULL,
  `requests` bigint unsigned NOT NULL DEFAULT '0',
  `billable_requests` bigint unsigned NOT NULL DEFAULT '0',
  `tokens_input` bigint unsigned NOT NULL DEFAULT '0',
  `tokens_output` bigint unsigned NOT NULL DEFAULT '0',
  `tokens_cache_read` bigint unsigned NOT NULL DEFAULT '0',
  `tokens_cache_write` bigint unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`window_start`,`bucket_scope`,`bucket_id`,`model`),
  CONSTRAINT `ck_uw_scope` CHECK ((`bucket_scope` in (_utf8mb4'key',_utf8mb4'group',_utf8mb4'global')))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `usage_windows` WRITE;
/*!40000 ALTER TABLE `usage_windows` DISABLE KEYS */;
INSERT INTO `usage_windows` (`window_start`, `bucket_scope`, `bucket_id`, `model`, `requests`, `billable_requests`, `tokens_input`, `tokens_output`, `tokens_cache_read`, `tokens_cache_write`) VALUES (0,'key','vk_55cb1808aabb09e6e14e517d91ce0c13','m-cache',4,3,7,7,4,0);
INSERT INTO `usage_windows` (`window_start`, `bucket_scope`, `bucket_id`, `model`, `requests`, `billable_requests`, `tokens_input`, `tokens_output`, `tokens_cache_read`, `tokens_cache_write`) VALUES (0,'key','vk_55cb1808aabb09e6e14e517d91ce0c13','m-chat',4,3,22,14,0,0);
INSERT INTO `usage_windows` (`window_start`, `bucket_scope`, `bucket_id`, `model`, `requests`, `billable_requests`, `tokens_input`, `tokens_output`, `tokens_cache_read`, `tokens_cache_write`) VALUES (0,'key','vk_c178b4fe1d02f68e5583171e0dc5b7c2','m-cache',2,2,7,7,4,0);
INSERT INTO `usage_windows` (`window_start`, `bucket_scope`, `bucket_id`, `model`, `requests`, `billable_requests`, `tokens_input`, `tokens_output`, `tokens_cache_read`, `tokens_cache_write`) VALUES (0,'key','vk_c178b4fe1d02f68e5583171e0dc5b7c2','m-chat',2,2,11,7,0,0);
INSERT INTO `usage_windows` (`window_start`, `bucket_scope`, `bucket_id`, `model`, `requests`, `billable_requests`, `tokens_input`, `tokens_output`, `tokens_cache_read`, `tokens_cache_write`) VALUES (1791936000,'key','group:fixture@day','m-cache',4,3,7,7,4,0);
INSERT INTO `usage_windows` (`window_start`, `bucket_scope`, `bucket_id`, `model`, `requests`, `billable_requests`, `tokens_input`, `tokens_output`, `tokens_cache_read`, `tokens_cache_write`) VALUES (1791936000,'key','group:fixture@day','m-chat',4,3,22,14,0,0);
/*!40000 ALTER TABLE `usage_windows` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

