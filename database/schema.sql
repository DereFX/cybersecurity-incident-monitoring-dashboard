CREATE DATABASE IF NOT EXISTS cyber_soc
  CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE cyber_soc;

CREATE TABLE IF NOT EXISTS users (
    user_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(150) NOT NULL,
    email VARCHAR(255) NULL,
    department VARCHAR(150) NULL,
    role VARCHAR(100) NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'active',
    source_dataset VARCHAR(100) NOT NULL,
    external_user_id VARCHAR(150) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_users_status CHECK (status IN ('active', 'inactive', 'locked')),
    CONSTRAINT uq_users_source_external UNIQUE (source_dataset, external_user_id),
    INDEX ix_users_username (username),
    INDEX ix_users_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS systems (
    system_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    hostname VARCHAR(255) NULL,
    ip_address VARCHAR(45) NULL,
    os VARCHAR(150) NULL,
    system_type VARCHAR(100) NULL,
    location VARCHAR(255) NULL,
    owner_id BIGINT UNSIGNED NULL,
    source_dataset VARCHAR(100) NOT NULL,
    external_system_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_systems_owner FOREIGN KEY (owner_id) REFERENCES users(user_id)
        ON UPDATE RESTRICT ON DELETE SET NULL,
    CONSTRAINT uq_systems_source_external UNIQUE (source_dataset, external_system_id),
    INDEX ix_systems_ip_address (ip_address),
    INDEX ix_systems_owner (owner_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS analysts (
    analyst_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    role VARCHAR(100) NOT NULL,
    team VARCHAR(100) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX ix_analysts_team_active (team, active)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS threat_categories (
    category_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    category_name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(500) NOT NULL,
    default_severity VARCHAR(20) NOT NULL,
    CONSTRAINT ck_categories_severity CHECK (
        default_severity IN ('low', 'medium', 'high', 'critical')
    )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS incidents (
    incident_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NULL,
    system_id BIGINT UNSIGNED NULL,
    category_id BIGINT UNSIGNED NOT NULL,
    incident_time DATETIME(6) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'open',
    detected_by VARCHAR(150) NOT NULL,
    source_dataset VARCHAR(100) NOT NULL,
    source_event_id VARCHAR(255) NULL,
    detection_key CHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    resolved_at DATETIME(6) NULL,
    CONSTRAINT fk_incidents_user FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON UPDATE RESTRICT ON DELETE SET NULL,
    CONSTRAINT fk_incidents_system FOREIGN KEY (system_id) REFERENCES systems(system_id)
        ON UPDATE RESTRICT ON DELETE SET NULL,
    CONSTRAINT fk_incidents_category FOREIGN KEY (category_id)
        REFERENCES threat_categories(category_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_incidents_severity CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT ck_incidents_status CHECK (
        status IN ('open', 'assigned', 'investigating', 'resolved', 'false_positive')
    ),
    CONSTRAINT uq_incidents_detection_key UNIQUE (detection_key),
    INDEX ix_incidents_time (incident_time),
    INDEX ix_incidents_status_severity (status, severity),
    INDEX ix_incidents_user (user_id),
    INDEX ix_incidents_system (system_id),
    INDEX ix_incidents_category (category_id),
    INDEX ix_incidents_source (source_dataset, source_event_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS assignments (
    assignment_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT UNSIGNED NOT NULL,
    analyst_id BIGINT UNSIGNED NOT NULL,
    assigned_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    resolved_at DATETIME(6) NULL,
    response_action TEXT NULL,
    comments TEXT NULL,
    CONSTRAINT fk_assignments_incident FOREIGN KEY (incident_id)
        REFERENCES incidents(incident_id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_assignments_analyst FOREIGN KEY (analyst_id)
        REFERENCES analysts(analyst_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    INDEX ix_assignments_incident (incident_id, assigned_at),
    INDEX ix_assignments_analyst_open (analyst_id, resolved_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS incident_audit_log (
    audit_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT UNSIGNED NOT NULL,
    analyst_id BIGINT UNSIGNED NULL,
    action VARCHAR(100) NOT NULL,
    old_status VARCHAR(30) NULL,
    new_status VARCHAR(30) NULL,
    notes TEXT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_audit_incident FOREIGN KEY (incident_id)
        REFERENCES incidents(incident_id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_audit_analyst FOREIGN KEY (analyst_id)
        REFERENCES analysts(analyst_id) ON UPDATE RESTRICT ON DELETE SET NULL,
    INDEX ix_audit_incident_time (incident_id, created_at)
) ENGINE=InnoDB;

