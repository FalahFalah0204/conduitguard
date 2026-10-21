import json

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
SAMPLE = {
    "default_policy": "deny",
    "rules": [
        {"id": "web", "source": "*", "destination": "192.0.2.10", "protocol": "tcp", "port": 443, "action": "allow"}
    ],
}


def test_health_and_openapi():
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.get("/openapi.json").status_code == 200


def test_validate_empty_bad_json_and_valid_config():
    assert client.post("/api/validate", content=b"").status_code == 400
    assert client.post("/api/validate", content=b"{").json()["error"]["code"] == "invalid_json"
    assert client.post("/api/validate", json=SAMPLE).json() == {"valid": True, "rule_count": 1}


def test_analyze_and_schema_failure():
    payload = {"before": SAMPLE, "after": SAMPLE, "probes": []}
    result = client.post("/api/analyze", json=payload)
    assert result.status_code == 200 and result.json()["findings"] == []
    bad = client.post(
        "/api/analyze",
        content=json.dumps({"before": SAMPLE, "after": {}}),
        headers={"content-type": "application/json"},
    )
    assert bad.status_code == 422
    assert "traceback" not in bad.text.lower()


def test_body_limit():
    response = client.post(
        "/api/validate",
        content=b" " * (256 * 1024 + 1),
        headers={"Origin": "http://localhost:3000"},
    )
    assert response.status_code == 413
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_end_to_end_demo_analysis_and_invalid_input():
    demo = client.get("/api/examples/demo")
    assert demo.status_code == 200
    result = client.post("/api/analyze", json=demo.json())
    assert result.status_code == 200
    body = result.json()
    assert [x["id"] for x in body["changes"]["added"]] == ["allow-admin"]
    assert len(body["simulation"]["before"]) == len(demo.json()["probes"])
    assert len(body["simulation"]["after"]) == len(demo.json()["probes"])
    assert any(f["id"] == "CG-POL-002" for f in body["findings"])
    invalid = client.post("/api/analyze", content=b"{not-json", headers={"content-type": "application/json"})
    assert invalid.status_code == 422
