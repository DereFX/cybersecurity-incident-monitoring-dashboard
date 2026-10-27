CYBERSECURITY PROJECT DEVELOPMENT DATASETS

Files
-----
1. rba_authentication_events_dev.csv
   20k+ authentication events, including planted repeated-failed-login sequences.

2. unsw_nb15_network_events_dev.csv
   15k network-flow events covering Normal plus the nine UNSW-NB15 attack categories.

3. *_quickstart.csv
   Smaller files for rapid Codex development and unit/integration tests.

IMPORTANT PROVENANCE NOTE
-------------------------
These are REPRESENTATIVE DEVELOPMENT DATASETS generated for the academic prototype.
They preserve the public field concepts, data types, categories, and use cases of the
RBA login dataset and UNSW-NB15, but they are NOT verbatim samples copied from the
original large source files.

Use the original datasets as the cited academic sources:
- RBA: Zenodo record 6782156
- UNSW-NB15: UNSW Canberra dataset page

Recommended usage
-----------------
MongoDB:
- Store rows from both CSVs as raw/semi-structured security events.

MySQL:
- Derive/store users, systems, incidents, threat_categories, analysts, assignments.

Python:
- Repeated failed login: >=5 failures for a user/IP within 5 minutes.
- Suspicious access: same user across multiple IPs/devices in a short window.
- Network threat handling: use label + attack_cat for the prototype's event/incident logic.

Do NOT claim these two datasets describe the same real users or sessions.
If cross-source correlation is needed, create explicitly labeled synthetic demo mappings.
