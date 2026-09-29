# Implementation plan

## Phase 1 - Dataset inspection and mappings

- [x] Inspect repository without overwriting existing work.
- [x] Inspect the actual quickstart schemas and dataset README.
- [x] Record provenance and prevent cross-dataset identity correlation.
- [x] Implement configurable mappings, schema validation, and normalization.
- [x] Add synthetic unit fixtures and loader tests.
- [x] Run the loaders against the complete quickstart files.

Dataset scope: use only the supplied ZIP files. Begin with both quickstart
CSVs, then switch to both dev CSVs after the pipeline passes.

## Phase 2 - Persistence

- [x] Create the normalized MySQL schema, constraints, indexes, seeds, and
  stored procedures.
- [x] Create MongoDB connections, indexes, idempotent batch ingestion, and paging.
- Add integration tests that are skipped unless test databases are configured.

## Phase 3 - ETL integration

- [x] Store normalized authentication and network envelopes in `security_events`.
- [x] Derive only defensible MySQL users/systems; preserve nullable relationships.
- [x] Add summaries and duplicate handling.
- [ ] Add persistent import-batch records and source-file content hashes.

## Phase 4 - Detection and incidents

- [x] Implement failed-login and suspicious-access rolling-window rules.
- [x] Implement explainable network rules/statistical thresholds without ML.
- [ ] Evaluate network alerts against labels only after detection.
- [x] Create deduplicated MySQL incidents and MongoDB alert evidence.

## Phase 5 - Advanced queries

- [x] Add 8-10 documented SQL queries and stored procedures.
- [x] Add at least five tested MongoDB aggregation pipelines.

## Phase 6 - Streamlit

- [x] Build the five required pages and persist assignment/status actions.
- [x] Clearly label source annotations separately from generated alerts.
- [x] Add configurable, schema-detected, size-limited CSV upload.
- [ ] Finish response-action/resolution forms.

## Phase 7 - Verification and delivery

- Complete unit/integration tests, documentation, diagrams, setup scripts, and
  a reproducible end-to-end synthetic demonstration.
- Switch from quickstart to dev CSVs only after the quickstart pipeline passes.
