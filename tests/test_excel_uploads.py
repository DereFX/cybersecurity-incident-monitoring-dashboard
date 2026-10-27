"""Excel fixtures are explicitly synthetic unless converted from supplied CSVs."""

from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd
import pytest
from openpyxl import Workbook

from detection.failed_login import detect_repeated_failed_logins
from detection.suspicious_access import detect_suspicious_access
from etl.authentication_loader import load_authentication_frame
from etl.demo_data import authentication_demo_csv
from etl.models import DatasetValidationError
from etl.network_loader import load_network_frame
from etl.schema_detection import detect_dataset_type
from etl.tabular_reader import read_security_table, workbook_sheets
from etl.upload_history import UploadHistory, namespace_upload_events


def demo_frame():
    return pd.read_csv(BytesIO(authentication_demo_csv("excel-fixture", datetime(2026, 10, 1, tzinfo=timezone.utc))))


def workbook_bytes(sheets):
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        for name, frame in sheets.items():
            frame.to_excel(writer, sheet_name=name, index=False)
    output.seek(0)
    return output


def test_excel_authentication_uses_existing_detection_and_preserves_context():
    data = workbook_bytes({"Authentication": demo_frame()})
    assert workbook_sheets(data) == ["Authentication"]
    frame = read_security_table(data, filename="synthetic.xlsx")
    assert detect_dataset_type(frame.columns) == "authentication"
    result = load_authentication_frame(frame, source_dataset="synthetic_excel")
    assert len(result.events) == 12
    assert len(detect_repeated_failed_logins(result.events)) == 1
    assert len(detect_suspicious_access(result.events)) == 1
    assert result.events[0].source_dataset == "synthetic_excel"
    assert result.events[0].raw_event["failure_reason"] is None or isinstance(result.events[0].raw_event["failure_reason"], str)
    assert data.tell() == 0


def test_excel_network_matches_csv_predictions_with_saved_model():
    from detection.ml_network import detect_ml_network_activity
    supplied = pd.read_csv("data/raw/unsw_nb15_network_events_quickstart.csv", nrows=25)
    excel = read_security_table(workbook_bytes({"Flows": supplied}), filename="flows.xlsx")
    assert detect_dataset_type(excel.columns) == "network"
    first = load_network_frame(supplied, source_dataset="excel_parity").events
    second = load_network_frame(excel, source_dataset="excel_parity").events
    assert [e.event_id for e in first] == [e.event_id for e in second]
    csv_alerts = detect_ml_network_activity(first, probability_threshold=0.01)
    xlsx_alerts = detect_ml_network_activity(second, probability_threshold=0.01)
    assert [a.detection_key for a in xlsx_alerts] == [a.detection_key for a in csv_alerts]
    assert [a.evidence["attack_probability"] for a in xlsx_alerts] == pytest.approx(
        [a.evidence["attack_probability"] for a in csv_alerts])


def test_worksheet_selection_is_explicit_and_does_not_merge_sheets():
    data = workbook_bytes({"First": demo_frame(), "Other": demo_frame().iloc[:4]})
    assert workbook_sheets(data) == ["First", "Other"]
    with pytest.raises(DatasetValidationError, match="Select one"):
        read_security_table(data, filename="synthetic.xlsx")
    assert len(read_security_table(data, filename="synthetic.xlsx", sheet_name="Other")) == 4
    with pytest.raises(DatasetValidationError, match="does not exist"):
        read_security_table(data, filename="synthetic.xlsx", sheet_name="Missing")


def test_excel_preview_reads_only_first_ten_rows():
    data = workbook_bytes({"Events": demo_frame()})
    assert len(read_security_table(data, filename="synthetic.XLSX", nrows=10)) == 10


def test_excel_ids_and_native_datetimes_are_not_lost():
    frame = demo_frame().iloc[:1].copy()
    frame["user_id"] = "00042"
    frame["login_timestamp"] = datetime(2026, 10, 1, 10, 0)
    loaded = load_authentication_frame(read_security_table(workbook_bytes({"Events": frame}), filename="fixture.xlsx"))
    assert loaded.events[0].user_id == "00042"
    assert loaded.events[0].timestamp == datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("value, expected", [("FALSE", "failure"), ("true", "success"), (0, "failure"), (1, "success")])
def test_excel_boolean_cells(value, expected):
    frame = demo_frame().iloc[:1].copy()
    frame["login_successful"] = value
    loaded = load_authentication_frame(read_security_table(workbook_bytes({"Events": frame}), filename="fixture.xlsx"))
    assert loaded.events[0].authentication_result == expected


@pytest.mark.parametrize("kind", ["timestamp", "schema", "boolean", "empty_rows"])
def test_excel_reuses_validation(kind):
    frame = demo_frame()
    if kind == "timestamp": frame.loc[0, "login_timestamp"] = "not-a-time"
    if kind == "schema": frame = frame.drop(columns="user_id")
    if kind == "boolean": frame["login_successful"] = "uncertain"
    if kind == "empty_rows": frame = frame.iloc[:0]
    parsed = read_security_table(workbook_bytes({"Events": frame}), filename="fixture.xlsx")
    with pytest.raises(DatasetValidationError):
        load_authentication_frame(parsed)


@pytest.mark.parametrize("headers", [[], ["event_id", "event_id"], ["event_id", None, "user_id"]])
def test_empty_or_invalid_excel_headers(headers):
    book = Workbook()
    if headers: book.active.append(headers)
    data = BytesIO(); book.save(data)
    with pytest.raises(DatasetValidationError):
        read_security_table(data, filename="fixture.xlsx")


def test_formula_beyond_preview_is_rejected_on_full_import():
    frame = demo_frame()
    frame.loc[11, "failure_reason"] = "=1+1"
    data = workbook_bytes({"Events": frame})
    assert len(read_security_table(data, filename="fixture.xlsx", nrows=10)) == 10
    with pytest.raises(DatasetValidationError, match="formulas"):
        read_security_table(data, filename="fixture.xlsx")


def test_invalid_excel_and_unsupported_extensions_have_meaningful_errors():
    with pytest.raises(DatasetValidationError, match="valid .xlsx"):
        workbook_sheets(BytesIO(b"not a workbook"))
    with pytest.raises(DatasetValidationError, match="older .xls"):
        read_security_table(BytesIO(b"not supported"), filename="old.xls")


def test_expanded_workbook_limit(monkeypatch):
    from etl import tabular_reader
    monkeypatch.setattr(tabular_reader, "MAX_WORKBOOK_BYTES", 1)
    with pytest.raises(DatasetValidationError, match="expanded-size"):
        workbook_sheets(workbook_bytes({"Events": demo_frame()}))


def test_same_workbook_sheet_is_stable_and_different_sheets_are_isolated():
    database = MagicMock()
    library = UploadHistory(database)
    data = workbook_bytes({"First": demo_frame(), "Second": demo_frame()})
    content_hash = sha256(data.getvalue()).hexdigest()
    def identity(sheet):
        library.register("synthetic.xlsx", content_hash, len(data.getvalue()), sheet_name=sheet)
        return database.ingestion_uploads.update_one.call_args.args[0]["_id"]
    first, again, other = identity("First"), identity("First"), identity("Second")
    assert first == again and first != other
    events = load_authentication_frame(read_security_table(data, filename="synthetic.xlsx", sheet_name="First")).events
    namespace_upload_events(events, first)
    before = [e.event_id for e in events]
    namespace_upload_events(events, again)
    assert before == [e.event_id for e in events]
    metadata = database.ingestion_uploads.update_one.call_args.args[1]["$setOnInsert"]
    assert metadata["sheet_name"] == "Second"
    assert metadata["content_sha256"] == content_hash


def test_excel_uploader_preview_and_import_form(monkeypatch):
    from streamlit.testing.v1 import AppTest
    import streamlit as st
    from etl import upload_history, pipeline
    from ui import resources
    from ui import theme
    from ui import upload_history as upload_ui
    data = workbook_bytes({"Events": demo_frame()})
    data.name = "synthetic_ui.xlsx"
    data.size = len(data.getvalue())
    monkeypatch.setattr(st, "file_uploader", lambda *a, **kw: data)
    # This focused page test omits navigation; test_dashboard covers the full app shell.
    monkeypatch.setattr(theme, "configure_page", lambda *a, **kw: None)
    monkeypatch.setattr(upload_ui, "render_upload_history", lambda: None)
    history = MagicMock()
    history.register.return_value = {"_id": "synthetic-sheet-id", "hidden": False}
    history.start_run.return_value = "synthetic-run"
    monkeypatch.setattr(upload_history, "UploadHistory", lambda database: history)
    monkeypatch.setattr(resources, "get_mongo", MagicMock())
    monkeypatch.setattr(resources, "get_mysql", MagicMock())
    calls = []
    def process(**kwargs):
        calls.append(kwargs)
        assert len(kwargs["authentication_events"]) == 12
        return pipeline.PipelineSummary(12, 0, 12, 0, 2, 2, 0, 2, 0)
    monkeypatch.setattr(pipeline, "process_events", process)
    # Avoid Streamlit re-uploading the injected file after its normal successful rerun.
    def finish(*args, **kwargs):
        monkeypatch.setattr(st, "file_uploader", lambda *a, **kw: None)
    history.finish.side_effect = finish
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "pages/4_Data_Ingestion.py")).run(timeout=20)
    assert not app.exception
    assert app.selectbox[0].value == "Events"
    assert any("authentication schema" in e.value for e in app.success)
    app.checkbox[0].check()
    next(b for b in app.button if b.label == "Validate, import & detect").click().run(timeout=20)
    assert not app.exception
    assert len(calls) == 1
    assert history.register.call_args.kwargs["sheet_name"] == "Events"
    assert any("synthetic_ui.xlsx / Events" in e.value for e in app.success)
