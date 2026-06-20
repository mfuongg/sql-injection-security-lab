CREATE DATABASE IF NOT EXISTS sql_injection_demo;
USE sql_injection_demo;

CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(30) NOT NULL,
    enabled BIT(1) NOT NULL DEFAULT b'1',
    two_factor_enabled BIT(1) NOT NULL DEFAULT b'0',
    two_factor_secret VARCHAR(120) NULL,
    last_totp_counter BIGINT NULL,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_time DATETIME NOT NULL,
    ip_address VARCHAR(100) NOT NULL,
    username_input VARCHAR(150),
    password_input VARCHAR(300),
    payload VARCHAR(500),
    login_mode VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    suspicious BIT(1) NOT NULL DEFAULT b'0',
    risk_level VARCHAR(30),
    risk_score INT,
    detector_result VARCHAR(1000),
    message VARCHAR(1500),
    query_preview VARCHAR(2000)
);

CREATE TABLE IF NOT EXISTS attack_payloads (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(120) NOT NULL UNIQUE,
    payload VARCHAR(500) NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    description VARCHAR(800),
    expected_vulnerable VARCHAR(500),
    expected_secure VARCHAR(500)
);
