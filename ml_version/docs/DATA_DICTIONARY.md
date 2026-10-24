# Dataset inspection and data dictionary

Inspection date: 2026-09-28

## Provenance and integrity boundary

The supplied archive says these CSVs are **representative development
datasets** that preserve public authentication and UNSW-NB15 field concepts.
They are not claimed to be verbatim official samples. This project uses only
the files supplied in `cybersecurity_project_datasets.zip`; it does not fetch
or depend on Kaggle or any other external dataset service.

The authentication and network files represent different environments. Values
such as users, IP addresses, devices, and timestamps must never be correlated
across sources unless a separately documented synthetic mapping is provided.

## Authentication quickstart

File: `rba_authentication_events_quickstart.csv`  
Inspected shape: 5,000 rows x 14 columns  
Timestamp field: `login_timestamp`  
Native event identifier: `event_id`

| Source column | Inspected type | Canonical use |
|---|---|---|
| event_id | string | event_id |
| login_timestamp | string timestamp | timestamp |
| user_id | string | user_id within this source only |
| ip_address | string | source_ip |
| country | string | raw geographic context |
| city | string | raw geographic context |
| device_id | string | device_id within this source only |
| device_type | string | raw device context |
| os | string | raw device context |
| browser | string | raw device context |
| login_successful | boolean | authentication_result |
| failure_reason | nullable string | raw failure evidence |
| is_attack_ip | boolean | observed source label only |
| is_account_takeover | boolean | observed source label only |

`failure_reason` is the only field with missing values in the inspected file
(4,503 missing). It is optional and must not cause row rejection.

## Network quickstart

File: `unsw_nb15_network_events_quickstart.csv`  
Inspected shape: 4,444 rows x 40 columns  
Timestamp field: `event_timestamp`  
Native row identifier: `id`

| Source columns | Meaning/use |
|---|---|
| id, event_timestamp | source identifier and event time |
| source_ip, destination_ip | flow endpoints |
| dur, proto, service, state | duration and protocol/service state |
| spkts, dpkts, sbytes, dbytes, rate | packet/byte volume and flow rate |
| sttl, dttl | source/destination time-to-live values |
| sload, dload, sloss, dloss | directional load and packet loss |
| sinpkt, dinpkt, sjit, djit | inter-packet timing and jitter |
| tcprtt, synack, ackdat | TCP round-trip/handshake timing |
| ct_srv_src, ct_state_ttl | connection-count features |
| ct_dst_ltm, ct_src_ltm | recent destination/source counts |
| ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm | recent endpoint/port counts |
| is_ftp_login, ct_ftp_cmd | FTP-related features |
| ct_flw_http_mthd | HTTP method-count feature |
| ct_srv_dst | recent service/destination count |
| is_sm_ips_ports | source/destination IP-port equality indicator |
| attack_cat | observed dataset category; never an independent detection |
| label | observed binary label; used only for later evaluation |

The inspected file has no missing values. Its observed categories are Normal
plus Analysis, Backdoors, DoS, Exploits, Fuzzers, Generic, Reconnaissance,
Shellcode, and Worms. The quickstart distribution is deliberately development-
oriented and should not be presented as a real-world prevalence estimate.

## Canonical MongoDB envelope

Every normalized event contains `event_id`, `timestamp`, `source_dataset`, and
`event_type`. Optional common fields are populated only when available:
`user_id`, `device_id`, `source_ip`, `destination_ip`, `protocol`,
`authentication_result`, and `attack_category`. The complete cleaned source row
is retained in `raw_event`, while provided labels are retained in
`original_labels` and never renamed to generated alerts.
