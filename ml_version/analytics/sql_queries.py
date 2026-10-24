"""Parameterized advanced SQL used by dashboards and demonstrations."""

INCIDENTS_WITH_CONTEXT = """
SELECT i.incident_id, i.incident_time, i.severity, i.status,
       tc.category_name, u.username, s.hostname,
       a.name AS assigned_analyst
FROM incidents i
JOIN threat_categories tc ON tc.category_id = i.category_id
LEFT JOIN users u ON u.user_id = i.user_id
LEFT JOIN systems s ON s.system_id = i.system_id
LEFT JOIN assignments assn
  ON assn.assignment_id = (
      SELECT MAX(a2.assignment_id) FROM assignments a2
      WHERE a2.incident_id = i.incident_id
  )
LEFT JOIN analysts a ON a.analyst_id = assn.analyst_id
ORDER BY i.incident_time DESC
"""

INCIDENT_COUNTS_BY_CATEGORY_SEVERITY = """
SELECT tc.category_name, i.severity, COUNT(*) AS incident_count
FROM incidents i
JOIN threat_categories tc ON tc.category_id = i.category_id
GROUP BY tc.category_name, i.severity
HAVING COUNT(*) >= %s
ORDER BY incident_count DESC
"""

AVERAGE_RESPONSE_TIME = """
SELECT tc.category_name,
       AVG(TIMESTAMPDIFF(SECOND, i.incident_time, i.resolved_at)) AS avg_seconds,
       COUNT(*) AS resolved_count
FROM incidents i
JOIN threat_categories tc ON tc.category_id = i.category_id
WHERE i.resolved_at IS NOT NULL
GROUP BY tc.category_name
ORDER BY avg_seconds DESC
"""

INCIDENTS_PER_USER = """
SELECT u.user_id, u.username, COUNT(i.incident_id) AS incident_count
FROM users u
LEFT JOIN incidents i ON i.user_id = u.user_id
GROUP BY u.user_id, u.username
ORDER BY incident_count DESC, u.username
"""

INCIDENTS_PER_SYSTEM = """
SELECT s.system_id, s.hostname, s.ip_address, COUNT(i.incident_id) AS incident_count
FROM systems s
LEFT JOIN incidents i ON i.system_id = s.system_id
GROUP BY s.system_id, s.hostname, s.ip_address
ORDER BY incident_count DESC, s.hostname
"""

ANALYST_WORKLOAD = """
SELECT a.analyst_id, a.name,
       COUNT(assn.assignment_id) AS total_assignments,
       SUM(assn.resolved_at IS NULL) AS active_assignments
FROM analysts a
LEFT JOIN assignments assn ON assn.analyst_id = a.analyst_id
GROUP BY a.analyst_id, a.name
ORDER BY active_assignments DESC, total_assignments DESC
"""

UNRESOLVED_CRITICAL_INCIDENTS = """
SELECT i.incident_id, i.incident_time, tc.category_name, i.description
FROM incidents i
JOIN threat_categories tc ON tc.category_id = i.category_id
WHERE i.severity = 'critical'
  AND i.status IN ('open', 'assigned', 'investigating')
ORDER BY i.incident_time ASC
"""

USERS_ABOVE_AVERAGE_INCIDENT_COUNT = """
SELECT u.user_id, u.username, COUNT(i.incident_id) AS incident_count
FROM users u
JOIN incidents i ON i.user_id = u.user_id
GROUP BY u.user_id, u.username
HAVING COUNT(i.incident_id) > (
    SELECT AVG(user_incident_count)
    FROM (
        SELECT COUNT(*) AS user_incident_count
        FROM incidents
        WHERE user_id IS NOT NULL
        GROUP BY user_id
    ) counts_per_user
)
ORDER BY incident_count DESC
"""

DAILY_INCIDENT_TREND = """
SELECT DATE(incident_time) AS incident_date,
       COUNT(*) AS daily_count,
       SUM(COUNT(*)) OVER (ORDER BY DATE(incident_time)) AS cumulative_count
FROM incidents
GROUP BY DATE(incident_time)
ORDER BY incident_date
"""

SOURCE_DATASET_SUMMARY = """
SELECT source_dataset,
       COUNT(*) AS incident_count,
       SUM(status IN ('open', 'assigned', 'investigating')) AS unresolved_count,
       SUM(severity IN ('high', 'critical')) AS serious_count
FROM incidents
GROUP BY source_dataset
ORDER BY incident_count DESC
"""

