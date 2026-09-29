# Cybersecurity Incident Monitoring & Threat Analytics Dashboard

A database-driven mini SOC built with Python, MySQL, MongoDB, and Streamlit.
Detection is explainable and rule/statistics based; this project does not train
or deploy machine-learning models.

## Current status

The quickstart pipeline and initial five-page Streamlit dashboard are working:
schema validation, normalization, MongoDB event/alert persistence, explainable
detection, deduplicated MySQL incidents, analytics, and incident assignment and
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
5. Run unit tests with `pytest -m "not integration"`.

Run the quickstart pipeline from the project root:

```powershell
python -m scripts.run_quickstart_pipeline
```

Start the dashboard:

```powershell
python -m streamlit run app.py
```

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
