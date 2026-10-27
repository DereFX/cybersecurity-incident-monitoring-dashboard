"""Run the unit suite and save a dated, inspectable report for the dashboard."""

from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def source_fingerprint() -> str:
    digest = hashlib.sha256()
    for folder in ("analytics", "config", "database", "detection", "etl", "incidents", "ml", "ui", "pages", "tests", "scripts"):
        for path in sorted((ROOT / folder).rglob("*.py")):
            digest.update(path.relative_to(ROOT).as_posix().encode())
            digest.update(path.read_bytes())
    digest.update((ROOT / "app.py").read_bytes())
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integration", action="store_true", help="Run opt-in live response integration checks with synthetic fixtures")
    options = parser.parse_args()
    output = ROOT / "reports"
    output.mkdir(exist_ok=True)
    xml_path = output / ("response_integration.xml" if options.integration else "unit_tests.xml")
    command = [sys.executable, "-m", "pytest", "-m", "integration" if options.integration else "not integration", "-q", f"--junitxml={xml_path}"]
    if options.integration:
        import os
        os.environ["SOC_RUN_INTEGRATION"] = "1"
        command.append("tests/test_response_integration.py")
    fingerprint = source_fingerprint()
    result = subprocess.run(command, cwd=ROOT, check=False)
    suites = ET.parse(xml_path).getroot().iter("testsuite")
    counts = {name: 0 for name in ("tests", "failures", "errors", "skipped")}
    for suite in suites:
        for name in counts:
            counts[name] += int(suite.get(name, "0"))
    report = {"checked_at_utc": datetime.now(timezone.utc).isoformat(), "exit_code": result.returncode,
              "scope": "Live MySQL/MongoDB synthetic workflow; SQL rolled back and synthetic MongoDB documents cleaned up" if options.integration else "Unit tests only; live database integration excluded", "counts": counts,
              "source_sha256": fingerprint, "command": "python scripts/verify_project.py" + (" --integration" if options.integration else "")}
    (output / ("response_integration.json" if options.integration else "verification.json")).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
