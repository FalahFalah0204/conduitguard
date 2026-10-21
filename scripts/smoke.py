"""Black-box smoke test for a running local API and production web app."""

import json
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

API = "http://127.0.0.1:8000"
WEB = "http://127.0.0.1:3000"


def wait_for(url: str) -> None:
    last_error = None
    for _ in range(30):
        try:
            with urlopen(url, timeout=2):
                return
        except Exception as error:
            last_error = error
            time.sleep(0.5)
    raise RuntimeError(f"Service did not become ready: {url}") from last_error


def get_json(url: str):
    with urlopen(url, timeout=10) as response:
        return response.status, json.load(response)


def post_json(url: str, payload):
    request = Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)


def main() -> None:
    wait_for(f"{API}/api/health")
    wait_for(WEB)
    with urlopen(WEB, timeout=10) as response:
        html = response.read().decode()
        assert response.status == 200
        assert "Validasi perubahan jaringan" in html

    status, health = get_json(f"{API}/api/health")
    assert status == 200 and health["status"] == "ok"
    status, example = get_json(f"{API}/api/examples/demo")
    assert status == 200
    status, report = post_json(f"{API}/api/analyze", example)
    assert status == 200
    assert [rule["id"] for rule in report["changes"]["added"]] == ["allow-admin"]
    assert any(item["id"] == "CG-POL-002" for item in report["findings"])
    assert len(report["simulation"]["before"]) == len(example["probes"])
    assert len(report["simulation"]["after"]) == len(example["probes"])

    status, invalid = post_json(f"{API}/api/analyze", {"before": example["before"], "after": {}})
    assert status == 422 and invalid["error"]["code"] == "validation_error"
    print("PASS: production page, API demo analysis, simulation, policy finding, and invalid-input response")


if __name__ == "__main__":
    main()
