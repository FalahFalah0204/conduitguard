# ConduitGuard

ConduitGuard is an open-source, offline tool for reviewing generic firewall policy changes. Supply a current policy, a proposed policy, and optional connection probes. The API validates both policies, produces an order-independent diff, runs explicit policy checks, evaluates each probe before and after, and returns a JSON report.

> **Simulation only.** ConduitGuard never connects to, scans, or applies changes to a firewall or network. Its generic model is not a vendor configuration parser and does not find every vulnerability.

## Features

- Strict JSON schema validation with required fields, types, address/CIDR checks, ID uniqueness, port bounds, rule and request size limits.
- Rule diff by rule ID. Reordering JSON arrays is not a change.
- Explainable checks for unrestricted allow rules, administrative ports, equal-priority conflicting rules, and broadened/new access.
- Offline connection evaluation against before and after configurations.
- Responsive Next.js interface with backend-loaded demo data, findings, diff, probe results, and downloadable JSON report.
- FastAPI endpoints with OpenAPI docs at `/docs`, consistent public validation errors, no public tracebacks, and request size limits.

## Architecture

```text
frontend (Next.js + TypeScript, :3000)
     | JSON REST calls; no policy decisions in the browser
backend (FastAPI + Pydantic, :8000)
     ├── app/models.py       schema and input validation
     ├── app/analysis.py     diff, policy engine, simulator, report data
     └── app/main.py         API, request size enforcement, error handling
```

The `POST /api/analyze` result includes changes, findings with evidence and mitigations, before/after probe decisions, recommendations, rules version, assumptions, and limitations. The browser adds a generation timestamp when downloading the report. The API is stateless and does not persist submitted configurations.

## Configuration schema

```json
{
  "default_policy": "deny",
  "rules": [
    {
      "id": "allow-https",
      "source": "10.20.0.0/16",
      "destination": "192.0.2.10",
      "protocol": "tcp",
      "port": 443,
      "action": "allow",
      "priority": 100,
      "description": "HTTPS from app subnet"
    }
  ]
}
```

`default_policy` is `allow` or `deny` (defaults to `deny`). `rules` is limited to 500 entries. Rule IDs are unique strings of up to 64 characters (`A-Z`, `a-z`, digits, `.`, `_`, `-`). `source` and `destination` are an IP address, CIDR network, or `*`. `protocol` is `tcp`, `udp`, `icmp`, or `any`. `port` is an integer from 1 through 65535 or `*`; ICMP uses `*` only. `action` is `allow` or `deny`. `priority` is an integer from 0 through 65535 and defaults to 100. Unknown fields are rejected.

### Evaluation semantics

Rules are evaluated by ascending numeric priority (lower number first), then ascending rule ID for ties. First match wins. `*` matches all values for its field; CIDR uses IP membership; `any` protocol matches TCP, UDP, or ICMP. A port number matches that exact TCP/UDP port. No match uses `default_policy`. Equal-priority overlapping rules with opposite actions produce a finding; the stable ID ordering still determines the simulated decision. Rule array position has no meaning.

The analyzer flags (1) an allow rule whose source and destination are both `*` or zero-prefix CIDRs, plus any `allow` default policy (high), (2) allow rules covering ports 22, 23, 3389, or 5900, including wildcard ports over TCP/UDP (high), (3) equal-priority opposite-action overlapping rules (medium), and (4) new or broadened access, including a deny-to-allow action change or a default-policy change to allow (medium, except a default-policy change is critical). These are heuristics, not a complete security policy.

### Probe schema

Provide an array of up to 100 probe objects with `source` and `destination` IP addresses, protocol `tcp`, `udp`, or `icmp`, a required integer `port` for TCP/UDP, and no port for ICMP. Optional `label` is shown in results. Probes only evaluate the supplied model; they do not test real connectivity.

## Clean installation

Requirements: Python 3.12+, Node.js 20.9+, pnpm 11, and Git (only needed for repository operations). From the repository root:

### Backend

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend\requirements.txt
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

### Frontend (second terminal)

```powershell
cd frontend
pnpm install --frozen-lockfile
pnpm dev
```

Open <http://localhost:3000>. Interactive API documentation is at <http://localhost:8000/docs> and the health check is <http://localhost:8000/api/health>. `NEXT_PUBLIC_API_URL` can point the frontend to another API origin; the backend CORS allow-list must also be adjusted in `backend/app/main.py` for that origin.

## API

- `GET /api/health` — API status and rules version.
- `GET /api/examples/demo` — demo input loaded by the interface.
- `POST /api/validate` — validates one configuration JSON document.
- `POST /api/analyze` — body is `{ "before": <config>, "after": <config>, "probes": [] }`.

Bodies larger than 256 KiB are rejected with HTTP 413. Invalid JSON sent to `/api/validate` returns 400. Schema errors return 422. Error bodies use `{ "error": { "code", "message", "details" } }`; unexpected errors are logged server-side and return a generic 500 response. The API schema is generated at `/openapi.json`.

## Testing and checks

From the repository root:

```powershell
python -m pytest
ruff check backend
ruff format --check backend
python -m pip install pip-audit
pip-audit -r backend/requirements.txt
cd frontend
pnpm install --frozen-lockfile
pnpm lint
pnpm exec tsc --noEmit
pnpm build
pnpm audit --audit-level=high
```

### Test results (Python 3.12.3, pytest 9.1.1)

```
platform win32 -- Python 3.12.3, pytest-9.1.1, pluggy-1.7.0
rootdir: conduitguard
configfile: pyproject.toml
collected 19 items

backend/tests/test_analysis.py::test_order_only_change_is_unchanged                          PASSED
backend/tests/test_analysis.py::test_added_removed_and_changed_are_reported                  PASSED
backend/tests/test_analysis.py::test_rejects_invalid_config[data0]                           PASSED
backend/tests/test_analysis.py::test_rejects_invalid_config[data1]                           PASSED
backend/tests/test_analysis.py::test_rejects_invalid_config[data2]                           PASSED
backend/tests/test_analysis.py::test_rejects_invalid_config[data3]                           PASSED
backend/tests/test_analysis.py::test_rejects_invalid_config[data4]                           PASSED
backend/tests/test_analysis.py::test_rejects_invalid_config[data5]                           PASSED
backend/tests/test_analysis.py::test_rejects_invalid_config[data6]                           PASSED
backend/tests/test_analysis.py::test_simulation_priority_wildcard_protocol_and_default       PASSED
backend/tests/test_analysis.py::test_policy_findings_cover_wide_admin_conflict_and_expansion PASSED
backend/tests/test_analysis.py::test_identical_configs_have_no_diff_findings_and_report_assumptions PASSED
backend/tests/test_analysis.py::test_existing_allow_default_is_flagged_even_without_a_change PASSED
backend/tests/test_analysis.py::test_zero_prefix_ranges_and_wildcard_admin_ports_are_flagged PASSED
backend/tests/test_api.py::test_health_and_openapi                                           PASSED
backend/tests/test_api.py::test_validate_empty_bad_json_and_valid_config                     PASSED
backend/tests/test_api.py::test_analyze_and_schema_failure                                   PASSED
backend/tests/test_api.py::test_body_limit                                                   PASSED
backend/tests/test_api.py::test_end_to_end_demo_analysis_and_invalid_input                   PASSED

19 passed, 1 warning in 0.44s
```

**Coverage by area:**

| Area | Tests | Result |
|------|-------|--------|
| Config parser — valid inputs | 5 | ✅ passed |
| Config parser — 7 invalid inputs (bad types, missing fields, duplicate IDs, invalid CIDR, ICMP+port) | 7 | ✅ passed |
| Diff engine — order-only, added, removed, changed | 2 | ✅ passed |
| Security policy findings — all 4 codes (CG-POL-001 to 004) | 3 | ✅ passed |
| Connectivity simulator — priority, wildcard, protocol, default | 1 | ✅ passed |
| API endpoints — health, validate, analyze, OpenAPI | 4 | ✅ passed |
| API error handling — 413 body limit, 422 schema error, CORS on error | 1 | ✅ passed |
| End-to-end demo flow | 1 | ✅ passed |
| **Total** | **19** | **✅ 19 passed** |

Tests cover malformed/empty/oversized payloads, missing and mistyped fields, duplicate IDs, identity and order-only diffs, added/removed/changed rules, policy checks, wildcard/protocol/port/priorities, allow/deny decisions, API errors, OpenAPI, and JSON-serializable reports. Simulator expectations are asserted directly against small fixtures. CI also runs `pip-audit -r backend/requirements.txt` and GitHub dependency review on pull requests.

For a black-box smoke test, start the backend as described above. In a second terminal, build and start the production frontend:

```powershell
cd frontend
pnpm install --frozen-lockfile
pnpm build
pnpm start --hostname 127.0.0.1 --port 3000
```

With both servers running, return to the repository root in another terminal and run `python scripts/smoke.py`. It checks the served production page, demo API, normal analysis and simulation, policy finding, and invalid-input response.

For browser-level workflow and accessibility checks, install the test dependency and Chromium once:

```powershell
python -m pip install -r scripts\e2e-requirements.txt
python -m playwright install chromium
```

With both servers running, execute `python scripts/browser_e2e.py`. The suite covers loading the demo, editing and analyzing policies, result navigation, validation/API errors, report export, keyboard focus, loading and empty states, and a 390 px mobile viewport. It runs axe-core 4.10.3 against WCAG 2.1 A/AA rules in desktop and mobile result views and writes `artifacts/accessibility-report.md` plus a machine-readable JSON report. The report includes automated findings, implemented fixes, and keyboard/label/mobile checks. Physical screen-reader testing remains a manual verification step.

## Examples

Use `examples/before.json`, `examples/after.json`, and `examples/probes.json` in the dashboard (or use **Load demo**, which fetches equivalent data from the API).

## Limitations

- This is a generic schema, not a parser for any vendor syntax.
- No routing, NAT, interfaces, statefulness, identity, zones, or actual network topology is modeled.
- Only the listed generic policy heuristics run; no claim of exhaustive vulnerability detection is made.
- Conflicting rules remain deterministic by rule ID but should be resolved by the operator.
- Inputs are not persisted by the API, but users should still avoid entering secrets or sensitive production details.
- See [SECURITY.md](SECURITY.md) for the explicitly allow-listed, unpatched high-severity frontend development dependency advisory.

## Troubleshooting

- **Dashboard says API unavailable:** start the backend on port 8000 and check `/api/health`; confirm `NEXT_PUBLIC_API_URL` and the CORS allow-list.
- **422 validation response:** inspect `error.details`; remove unsupported fields and confirm the schema and probe requirements above.
- **413 response:** reduce the combined request body to 256 KiB or less (500 rules per config; 100 probes).
- **Build tool not found:** install the documented Python, Node.js, and pnpm versions, then recreate the virtual environment and run `pnpm install --frozen-lockfile`.

## License

MIT. See [LICENSE](LICENSE).
