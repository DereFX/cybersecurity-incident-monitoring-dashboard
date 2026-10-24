# Evaluation rubric mapping

The Streamlit **Rubric & Evidence** page is the presentation layer for this mapping. It reports live database evidence where possible and never claims that a target mark is guaranteed.

| Rubric area | Marks | Primary implementation evidence |
|---|---:|---|
| Application Design & Functionality | 2 | Five Streamlit workflows; ETL → MongoDB → detection → MySQL incident → response; modular packages |
| Python Programming | 2 | Typed functions/classes, validation, exception and file handling, detection and incident services |
| SQL & NoSQL Integration | 2 | Normalised MySQL schema plus indexed MongoDB event and alert collections |
| Advanced Querying | 2 | `analytics/sql_queries.py`, `analytics/mongo_aggregations.py`, `database/procedures.sql` |
| Code Quality, Documentation & UI | 1 | README/setup docs, environment configuration, shared UI theme and five focused pages |
| Testing, Validation & Error Handling | 1 | Unit suite, separate integration tests, idempotency, malformed-input and failure cases |

## Functional demo path

1. Upload a supported CSV on **Data Pipeline**.
2. Validate and import events into MongoDB.
3. Run authentication rules and the trained network model.
4. Verify alerts and deduplicated MySQL incidents in the persistence summary.
5. Assign an analyst and update or resolve the incident on **Incident Response**.
6. Return to **Command Center** and **Threat Analytics** to show the updated metrics.

## Integrity and scope

- Authentication and network datasets retain separate provenance.
- Dataset attack labels are displayed for evaluation but are not treated as detector output.
- Synthetic records are labelled as synthetic demonstration data.
- Model metrics apply to the held-out supplied quickstart split and are not live-traffic guarantees.
