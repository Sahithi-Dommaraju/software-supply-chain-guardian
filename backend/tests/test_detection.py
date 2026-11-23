"""Run: .venv/Scripts/python -m tests.test_detection"""
from app.agents.change_detection import lookalike, within_one_edit
from app.agents.evidence import initial_risk
from app.agents.vulnerability import band, version_key

if __name__ == "__main__":
    assert within_one_edit("expres", "express") and within_one_edit("exrpess", "express")
    assert not within_one_edit("express", "express") and not within_one_edit("exp", "express")
    assert lookalike("expresss") == "express" and lookalike("express") is None and lookalike("@x/expresss") is None
    assert lookalike("cross_env") == "cross-env"
    assert [band(s) for s in (9.8, 7.0, 4.0, 0.5, 0.0)] == ["critical", "high", "medium", "low", "none"]
    assert version_key("4.17.12") > version_key("4.17.2")
    vuln = {"type": "vulnerability", "severity": "high", "severity_source": "CVSS score", "scope": "dev"}
    assert initial_risk(vuln)["level"] == "medium"          # dev-only lowers one level
    assert initial_risk({**vuln, "scope": "runtime"})["level"] == "high"
    assert initial_risk({**vuln, "severity": "unrated"})["level"] == "review"
    print("detection ok")
