USE cyber_soc;

DROP PROCEDURE IF EXISTS sp_user_security_summary;
DELIMITER //
CREATE PROCEDURE sp_user_security_summary(IN p_user_id BIGINT UNSIGNED)
BEGIN
    SELECT
        u.user_id,
        u.username,
        u.status AS user_status,
        COUNT(i.incident_id) AS total_incidents,
        SUM(i.status IN ('open', 'assigned', 'investigating')) AS unresolved_incidents,
        SUM(i.severity IN ('high', 'critical')) AS high_or_critical_incidents,
        MAX(i.incident_time) AS latest_incident_time,
        AVG(
            CASE WHEN i.resolved_at IS NOT NULL
                THEN TIMESTAMPDIFF(SECOND, i.incident_time, i.resolved_at)
            END
        ) AS average_resolution_seconds
    FROM users u
    LEFT JOIN incidents i ON i.user_id = u.user_id
    WHERE u.user_id = p_user_id
    GROUP BY u.user_id, u.username, u.status;
END//

DROP PROCEDURE IF EXISTS sp_resolve_incident//
CREATE PROCEDURE sp_resolve_incident(
    IN p_incident_id BIGINT UNSIGNED,
    IN p_analyst_id BIGINT UNSIGNED,
    IN p_response_action TEXT,
    IN p_comments TEXT
)
BEGIN
    DECLARE v_old_status VARCHAR(30);
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    START TRANSACTION;
    SELECT status INTO v_old_status
    FROM incidents WHERE incident_id = p_incident_id FOR UPDATE;

    IF v_old_status IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Incident not found';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM analysts WHERE analyst_id = p_analyst_id AND active = TRUE) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Active analyst not found';
    END IF;

    UPDATE incidents
    SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP(6)
    WHERE incident_id = p_incident_id;

    UPDATE assignments
    SET resolved_at = CURRENT_TIMESTAMP(6),
        response_action = p_response_action,
        comments = p_comments
    WHERE incident_id = p_incident_id
      AND analyst_id = p_analyst_id
      AND resolved_at IS NULL;

    INSERT INTO incident_audit_log
        (incident_id, analyst_id, action, old_status, new_status, notes)
    VALUES
        (p_incident_id, p_analyst_id, 'resolve', v_old_status, 'resolved', p_comments);
    COMMIT;
END//
DELIMITER ;

