# Cybersecurity Incident Monitoring & Threat Analytics Dashboard

A database-driven mini SOC built with Python, MySQL, MongoDB, Streamlit, and
scikit-learn. Authentication monitoring remains rule based. Network-flow
detection uses a trained random-forest classifier with a calibrated probability
threshold and held-out evaluation.

## Current status

The quickstart pipeline and seven-view Streamlit dashboard are working:
schema validation, normalization, MongoDB event/alert persistence, hybrid
rule/model detection, deduplicated MySQL incidents, analytics, incident assignment,
response actions and status updates. The dashboard includes a command center,
threat analytics, identity monitoring, incident response, data ingestion, and a
rubric/evidence view and Database Explorer. CSV uploads support automatic authentication/network schema
detection, a 25 MB limit, in-memory validation, configurable detection rules,
and duplicate-safe persistence. See `docs/IMPLEMENTATION_PLAN.md` and
`docs/DATA_DICTIONARY.md` and `docs/RUBRIC_MAPPING.md`.

The Database Explorer runs curated read-only SQL analyses, MongoDB pipelines and
the user-summary stored procedure. Incident Response links each case to its
MongoDB alert and source records using dataset provenance and detection keys.
Sidebar health checks report actual service availability and can be refreshed.

Generate a dated test report for the Evidence page:

```powershell
python scripts/verify_project.py
```

The report records a source fingerprint and warns when code has changed since
verification. Dashboard smoke tests use isolated database doubles; these do not
establish that live database integration works.

## Local setup

### CSV upload library

Data Pipeline keeps persistent per-file records in MongoDB `ingestion_uploads`
and per-import configurations, progress, results and failures in `ingestion_runs`.
The file identity uses its original filename and SHA-256 content hash. Reimports
of that file add attempts under the existing record; changed contents under the
same name create a separate entry. New uploads use file-scoped event IDs and
provenance so overlapping event IDs cannot mix evidence between CSVs.

Each CSV stays in the library. Switch **Include in dashboard** off to exclude
its events, alerts, incidents and related records from dashboard totals, charts,
incident lists, dataset selectors and Database Explorer reports. Switch it back
on to include the data again. Preferences persist across restarts; records are
never deleted. The file's import history remains available.

Data Pipeline automatically discovers **all existing source datasets** across
MySQL incidents, MongoDB events and MongoDB alerts and adds inclusion controls
for any sources that predate upload tracking. Existing source entries show
observed database counts and related local CSV downloads when files can be
identified. **Include existing data** controls the existing-source group, while
each source retains its individual switch. Registration does not reimport data,
change incident IDs or invent original upload timestamps, fingerprints or runs.
New uploads continue to retain their actual per-file and per-attempt metadata.

The interface uses muted sage-grey backgrounds with teal accents. Date and
dataset filters persist between operational views. In Command Center, select
a severity/category chart point to filter the queue, then choose **Open incident
details** to investigate the case. Analyst workload counts only current open
assignments. Resolution time measures from case creation to resolution, not
from the potentially historical or synthetic event date.

Data Pipeline includes a guided, explicitly synthetic CSV download: 12 events,
two expected alerts at default thresholds and a four-failure negative control.
Fresh downloads have unique event IDs; reimporting the same file is duplicate-safe.

Run the separate live workflow check with:

```powershell
python scripts/verify_project.py --integration
```

It checks real MongoDB event/alert writes and MySQL ingestion, deduplication,
assignment, response actions, resolution, workload and reopening. SQL fixture
rows are rolled back and only MongoDB documents belonging to that unique test
run are removed. The Evidence page loads the dated results from `reports/`.

After updating this version, refresh the stored procedure definitions with:

```powershell
python scripts/update_procedures.py
```

This uses the configured database and brings stored-procedure response-time
calculations into line with the dashboard. No schema migration is needed.
If the app account lacks routine-management privileges, run
`database/procedures.sql` in MySQL Workbench using an administrator account.

1. Install Python 3.11 or newer and create a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` and fill in database credentials when Phase 2
   connections are configured.
4. Place supplied CSV files under `data/raw/`; raw datasets are intentionally
   excluded from Git.
5. Train the network model with `python scripts/train_network_model.py`.
6. Run unit tests with `pytest -m "not integration"`.

Run the quickstart pipeline from the project root:

```powershell
python -m scripts.run_quickstart_pipeline
```

Start the dashboard:

```powershell
python -m streamlit run app.py
```

The model excludes `label`, `attack_cat`, event IDs, timestamps, and IP
addresses from its inputs. Its saved metadata records the data fingerprint,
split sizes, threshold, held-out metrics, feature list, and limitations. A high
held-out score is not a guarantee of performance on live traffic. The supplied
quickstart and development files are representative generated datasets, not
verbatim official UNSW-NB15 records.

Run the repeatable overfitting audit with:

```powershell
python scripts/audit_model_overfitting.py
```

The audit checks the training/test gap, nested five-fold validation,
chronological holdout performance, duplicate leakage, and development-only
records after removing every quickstart overlap.

Do not commit `.env`, raw datasets, or real security-event data.

The build uses only datasets supplied in `cybersecurity_project_datasets.zip`.
No Kaggle download or external dataset account is required.

## Local databases with Docker

Docker Desktop is the simplest local option. Copy `.env.example` to `.env`,
replace all placeholder passwords, ensure `MONGODB_URI` contains the same Mongo
password, start Docker Desktop, and run:

```powershell
docker compose up -d
```

On the first start, MySQL runs `schema.sql`, `seed.sql`, and `procedures.sql` in
that order. MongoDB indexes are created by the application connection layer.
Database integration tests are not part of the default unit-test command.

# Custom database queries

Open **Database Explorer → Custom SQL** or **Custom MongoDB**. Edit the starter query and click **Run**. Results can be downloaded as CSV or JSON. The original saved analyses remain available.

SQL accepts a single read-only `SELECT` over the listed project tables, including joins, grouping, subqueries and non-recursive CTEs. MongoDB accepts a JSON filter object or an aggregation array over `security_events` / `security_alerts`. The in-page guides include examples and field names.

Both editors apply the Data Pipeline CSV inclusion switches before querying; excluded files are not deleted. SQL is parsed with SQLGlot, table references are structurally scoped and exclusion values are bound parameters. Execution uses a read-only MySQL transaction. MongoDB writes, JavaScript, collection joins and external-source stages are blocked. Queries have a five-second server execution limit, a 500-row display limit and a 5 MB result-size check. This is a local educational query explorer, not an unrestricted public database console; do not expose the dashboard publicly without authentication and dedicated least-privilege database accounts.

Install updated dependencies with `python -m pip install -r requirements.txt` before restarting Streamlit.
