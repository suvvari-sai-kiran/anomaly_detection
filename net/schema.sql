CREATE DATABASE IF NOT EXISTS netmon_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'netmon_user'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON netmon_db.* TO 'netmon_user'@'localhost';
FLUSH PRIVILEGES;

USE netmon_db;

CREATE TABLE IF NOT EXISTS network_flows (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ts DATETIME NOT NULL,
  src_ip VARCHAR(45),
  dest_ip VARCHAR(45),
  protocol VARCHAR(16),
  packets BIGINT,
  bytes_sent BIGINT,
  is_anomaly TINYINT(1) DEFAULT 0,
  action_taken VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blocked_ips (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ip VARCHAR(45) UNIQUE,
  blocked_at DATETIME,
  device VARCHAR(100),
  reason VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

