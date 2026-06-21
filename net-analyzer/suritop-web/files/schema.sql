/*M!999999\- enable the sandbox mode */
-- MariaDB dump 10.19-11.8.5-MariaDB, for Linux (x86_64)
--
-- Host: localhost    Database: server_stats
-- ------------------------------------------------------
-- Server version       11.8.5-MariaDB-log

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*M!100616 SET @OLD_NOTE_VERBOSITY=@@NOTE_VERBOSITY, NOTE_VERBOSITY=0 */;

--
-- Table structure for table `conntrack_stats`
--

DROP TABLE IF EXISTS `conntrack_stats`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `conntrack_stats` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `connections` int(10) unsigned NOT NULL,
  `recorded_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_recorded` (`recorded_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cpu_temp`
--

DROP TABLE IF EXISTS `cpu_temp`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `cpu_temp` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `temp_c` decimal(5,1) NOT NULL,
  `recorded_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_recorded` (`recorded_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `f2b_actions`
--

DROP TABLE IF EXISTS `f2b_actions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `f2b_actions` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `action` enum('ban','unban') NOT NULL,
  `jail` varchar(100) NOT NULL,
  `src_ip` varchar(45) NOT NULL,
  `logged_at` datetime NOT NULL,
  `collected_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_logged` (`logged_at`),
  KEY `idx_jail` (`jail`),
  KEY `idx_src` (`src_ip`),
  KEY `idx_action_logged` (`action`,`logged_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `geo_cache`
--

DROP TABLE IF EXISTS `geo_cache`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `geo_cache` (
  `ip` varchar(45) NOT NULL,
  `lat` float NOT NULL,
  `lon` float NOT NULL,
  `country` varchar(100) DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `geoip_cache`
--

DROP TABLE IF EXISTS `geoip_cache`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `geoip_cache` (
  `ip` varchar(45) NOT NULL,
  `country_code` varchar(2) DEFAULT NULL,
  `country_name` varchar(100) DEFAULT NULL,
  `city` varchar(200) DEFAULT NULL,
  `cached_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ipt_drops`
--

DROP TABLE IF EXISTS `ipt_drops`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `ipt_drops` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `src_ip` varchar(45) NOT NULL,
  `dst_port` int(10) unsigned NOT NULL DEFAULT 0,
  `proto` varchar(10) NOT NULL DEFAULT 'TCP',
  `logged_at` datetime NOT NULL,
  `collected_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_logged` (`logged_at`),
  KEY `idx_src` (`src_ip`),
  KEY `idx_port` (`dst_port`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `nc_auth_fails`
--

DROP TABLE IF EXISTS `nc_auth_fails`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `nc_auth_fails` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `src_ip` varchar(45) NOT NULL,
  `username` varchar(100) NOT NULL DEFAULT '',
  `event_type` varchar(50) NOT NULL,
  `message` varchar(500) DEFAULT NULL,
  `logged_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_logged` (`logged_at`),
  KEY `idx_ip` (`src_ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `net_traffic`
--

DROP TABLE IF EXISTS `net_traffic`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `net_traffic` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `interface` varchar(20) NOT NULL DEFAULT '',
  `rx_mbytes_s` decimal(10,3) DEFAULT NULL COMMENT 'MB/s входящий',
  `tx_mbytes_s` decimal(10,3) DEFAULT NULL COMMENT 'MB/s исходящий',
  `rx_bytes` bigint(20) unsigned DEFAULT NULL COMMENT 'байт за интервал',
  `tx_bytes` bigint(20) unsigned DEFAULT NULL COMMENT 'байт за интервал',
  `recorded_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_recorded` (`recorded_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `nginx_blocks`
--

DROP TABLE IF EXISTS `nginx_blocks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `nginx_blocks` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `src_ip` varchar(45) NOT NULL,
  `method` varchar(10) NOT NULL DEFAULT 'GET',
  `uri` varchar(500) NOT NULL,
  `status` int(10) unsigned NOT NULL,
  `user_agent` varchar(500) DEFAULT NULL,
  `log_source` varchar(100) NOT NULL,
  `logged_at` datetime NOT NULL,
  `collected_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_logged` (`logged_at`),
  KEY `idx_src` (`src_ip`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ssh_attacks`
--

DROP TABLE IF EXISTS `ssh_attacks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `ssh_attacks` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `src_ip` varchar(45) NOT NULL,
  `username` varchar(100) NOT NULL,
  `attack_type` enum('failed_password','invalid_user') NOT NULL DEFAULT 'failed_password',
  `logged_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_logged` (`logged_at`),
  KEY `idx_ip` (`src_ip`),
  KEY `idx_user` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `suricata_alerts`
--

DROP TABLE IF EXISTS `suricata_alerts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `suricata_alerts` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `src_ip` varchar(45) NOT NULL,
  `dst_port` int(10) unsigned DEFAULT 0,
  `proto` varchar(10) DEFAULT '',
  `sig_id` int(10) unsigned DEFAULT 0,
  `sig_msg` varchar(512) DEFAULT '',
  `category` varchar(255) DEFAULT '',
  `severity` tinyint(3) unsigned DEFAULT 3,
  `action` varchar(20) DEFAULT 'allowed',
  `logged_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_logged` (`logged_at`),
  KEY `idx_ip` (`src_ip`),
  KEY `idx_sig` (`sig_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `system_load`
--

DROP TABLE IF EXISTS `system_load`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `system_load` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `load_1m` decimal(6,2) DEFAULT NULL,
  `load_5m` decimal(6,2) DEFAULT NULL,
  `load_15m` decimal(6,2) DEFAULT NULL,
  `ram_used_mb` decimal(10,1) DEFAULT NULL,
  `ram_total_mb` decimal(10,1) DEFAULT NULL,
  `recorded_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_recorded` (`recorded_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `waf_blocks`
--

DROP TABLE IF EXISTS `waf_blocks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `waf_blocks` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `src_ip` varchar(45) NOT NULL,
  `host` varchar(255) DEFAULT '',
  `uri` varchar(2048) DEFAULT '',
  `method` varchar(10) DEFAULT '',
  `rule_id` int(10) unsigned DEFAULT 0,
  `rule_msg` varchar(512) DEFAULT '',
  `status_code` smallint(5) unsigned DEFAULT 403,
  `severity` tinyint(3) unsigned DEFAULT 0,
  `logged_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_logged` (`logged_at`),
  KEY `idx_ip` (`src_ip`),
  KEY `idx_rule` (`rule_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*M!100616 SET NOTE_VERBOSITY=@OLD_NOTE_VERBOSITY */;

-- Dump completed on 2026-06-17 23:44:02