USE cyber_soc;

INSERT INTO threat_categories (category_name, description, default_severity) VALUES
    ('Repeated Failed Login', 'Configured count of failed authentication attempts within a rolling window.', 'high'),
    ('Suspicious Access', 'Rapid access from multiple distinct IP/device combinations.', 'medium'),
    ('Abnormal Network Activity', 'Flow feature exceeded an explainable statistical or rule threshold.', 'medium')
ON DUPLICATE KEY UPDATE description = VALUES(description), default_severity = VALUES(default_severity);

INSERT INTO analysts (name, role, team)
SELECT 'Demo Analyst', 'SOC Analyst', 'College SOC'
WHERE NOT EXISTS (
    SELECT 1 FROM analysts WHERE name = 'Demo Analyst' AND team = 'College SOC'
);

