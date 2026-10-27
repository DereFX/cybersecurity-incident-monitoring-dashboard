# Cybersecurity Incident Monitoring & Threat Analytics Dashboard

A database-driven mini SOC built with Python, MySQL, MongoDB, Streamlit, and
scikit-learn. Authentication monitoring remains rule based. Network-flow
detection uses a trained random-forest classifier with a calibrated probability
threshold and held-out evaluation.

## One current application

The latest sage/teal dashboard, trained network model, CSV/Excel imports and all
seven views now live at the repository root. There is no separate old app or
`ml_version` directory to choose between. On GitHub, use the **main2** branch.

From the repository folder, activate your environment and launch:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Use your existing `.env`; do not overwrite it when updating. The saved trained
model is included in `models/`, so retraining is optional. Existing MySQL and
MongoDB data do not need to be reimported or reset on this laptop. The supplied
generated quickstart/development CSVs are included in `data/raw/`. Generated
reports and presentations are included in `output/`. Credentials are excluded.

### Run on another laptop (without Docker)

Clone the current branch:

```powershell
git clone --branch main2 --single-branch https://github.com/DereFX/cybersecurity-incident-monitoring-dashboard.git
cd cybersecurity-incident-monitoring-dashboard
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Install and start MySQL 8+ and MongoDB Community Server on that laptop. In
MySQL Workbench, open and execute `database/schema.sql`, then `database/seed.sql`,
then `database/procedures.sql` as an administrator. These scripts use the
`cyber_soc` database. Configure `.env` with that laptop's own database username,
password and MongoDB URI. For a local MongoDB installation without authentication,
the URI is `mongodb://localhost:27017/`; use an authenticated URI if authentication
is enabled. Never upload `.env` to GitHub.

Then import the bundled data and launch the app:

```powershell
python -m scripts.run_quickstart_pipeline
python -m streamlit run app.py
```

The theme, features, trained model, datasets and report files are included.
Existing database contents are not exported: the other laptop starts with freshly
imported incidents and will not have this laptop's assignments, upload history,
visibility preferences or exact dashboard counts. Model retraining is optional.

## Current status

The quickstart pipeline and seven-view Streamlit dashboard are working:
schema validation, normalization, MongoDB event/alert persistence, hybrid
rule/model detection, deduplicated MySQL incidents, analytics, incident assignment,
response actions and status updates. The dashboard includes a command center,
threat analytics, identity monitoring, incident response, data ingestion, and a
rubric/evidence view and Database Explorer. CSV and Excel (.xlsx) uploads support automatic authentication/network schema
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

### CSV and Excel upload library

Excel uploads use `openpyxl`; install/update dependencies with
`python -m pip install -r requirements.txt` in this directory. In Data Pipeline,
choose an `.xlsx` workbook, select **Excel worksheet to import**, inspect the
preview, confirm the source-label checkbox and click **Validate, import & detect**.
The existing detection/model and MySQL/MongoDB pipeline is unchanged.

Row 1 must contain the same column names as the supported CSV schema. Import
one worksheet at a time; other sheets are not silently combined. Blank rows are
ignored. Use native values (not formulas); encrypted/corrupt files and `.xls` or
`.xlsm` files are not supported. Save those files as a values-only `.xlsx` first.
Limits: 25 MB uploaded, 100 MB expanded workbook content, 100,000 rows and 256
columns per worksheet. Text identifiers such as `00042` remain text if the cells
are stored as text in Excel. Numeric cells cannot recover zeros Excel has removed.

Each workbook worksheet has an independent library entry/inclusion switch.
Identity uses filename, actual file SHA-256 and worksheet name. Reimporting the
same bytes and worksheet is duplicate-safe; a different sheet or changed file
gets separate provenance. Uploading a CSV and its Excel conversion creates two
separate sources by design. Review inclusion switches to avoid counting both.
CSV and Excel use the same current application and database pipeline.

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
3. Copy `.env.example` to `.env`, configure local database credentials and initialize
   MySQL as described above.
4. Use the supplied generated CSV files already included under `data/raw/`.
5. Use the included model, or optionally retrain with `python scripts/train_network_model.py`.
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

Do not commit `.env` or private/real security-event data. The four supplied
generated academic datasets are explicitly included; other raw files remain ignored.

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
