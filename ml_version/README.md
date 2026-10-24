# Cybersecurity Incident Monitoring & Threat Analytics Dashboard

A database-driven mini SOC built with Python, MySQL, MongoDB, Streamlit, and
scikit-learn. Authentication monitoring remains rule based. Network-flow
detection uses a trained random-forest classifier with a calibrated probability
threshold and held-out evaluation.

## Current status

The quickstart pipeline and initial five-page Streamlit dashboard are working:
schema validation, normalization, MongoDB event/alert persistence, hybrid
rule/model detection, deduplicated MySQL incidents, analytics, and incident assignment and
status updates. CSV uploads support automatic authentication/network schema
detection, a 25 MB limit, in-memory validation, configurable detection rules,
and duplicate-safe persistence. See `docs/IMPLEMENTATION_PLAN.md` and
`docs/DATA_DICTIONARY.md`.

## Local setup

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
