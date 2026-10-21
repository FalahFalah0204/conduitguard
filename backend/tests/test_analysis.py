import json

import pytest
from pydantic import ValidationError

from app.analysis import analyze, diff_configs, simulate
from app.models import AnalyzeRequest, FirewallConfig


def config(rules, default="deny"):
    return FirewallConfig.model_validate({"default_policy": default, "rules": rules})


def rule(id="web", **changes):
    value = {
        "id": id,
        "source": "10.0.0.0/8",
        "destination": "192.0.2.10",
        "protocol": "tcp",
        "port": 443,
        "action": "allow",
        "priority": 100,
    }
    return {**value, **changes}


def test_order_only_change_is_unchanged():
    a, b = rule("a"), rule("b", port=8443)
    diff = diff_configs(config([a, b]), config([b, a]))
    assert diff["changed"] == [] and diff["added"] == [] and diff["removed"] == []
    assert diff["unchanged"] == ["a", "b"]


def test_added_removed_and_changed_are_reported():
    before = config([rule("same"), rule("gone")])
    after = config([rule("same", port=80), rule("new")])
    diff = diff_configs(before, after)
    assert [r["id"] for r in diff["added"]] == ["new"]
    assert [r["id"] for r in diff["removed"]] == ["gone"]
    assert diff["changed"][0]["id"] == "same"


@pytest.mark.parametrize(
    "data",
    [
        {"rules": [{"id": "x"}]},
        {"default_policy": "drop", "rules": []},
        {"rules": [rule("x", port=70000)]},
        {"rules": [rule("x", port="443")]},
        {"rules": [rule("x"), rule("x")]},
        {"rules": [rule("x", source="evil-host")]},
        {"rules": [rule("x", protocol="icmp", port=80)]},
    ],
)
def test_rejects_invalid_config(data):
    with pytest.raises(ValidationError):
        FirewallConfig.model_validate(data)


def test_simulation_priority_wildcard_protocol_and_default():
    cfg = config(
        [
            rule("allow-web", source="*", destination="*", protocol="any", port="*", priority=20),
            rule(
                "deny-web",
                source="203.0.113.0/24",
                destination="192.0.2.10",
                protocol="tcp",
                port=443,
                action="deny",
                priority=1,
            ),
        ]
    )
    probes = AnalyzeRequest.model_validate(
        {
            "before": cfg.model_dump(),
            "after": cfg.model_dump(),
            "probes": [
                {"source": "203.0.113.5", "destination": "192.0.2.10", "protocol": "tcp", "port": 443},
                {"source": "198.51.100.2", "destination": "192.0.2.10", "protocol": "udp", "port": 53},
            ],
        }
    ).probes
    result = simulate(cfg, probes)
    assert [(x["decision"], x["matched_rule_id"]) for x in result] == [("deny", "deny-web"), ("allow", "allow-web")]


def test_policy_findings_cover_wide_admin_conflict_and_expansion():
    before = config([rule("ssh", port=22, source="10.0.0.0/24")])
    after = config(
        [
            rule("ssh", port=22, source="*"),
            rule("wide", source="*", destination="*", port="*"),
            rule("deny", source="*", destination="*", port="*", action="deny"),
        ]
    )
    result = analyze(AnalyzeRequest(before=before, after=after))
    ids = {item["id"] for item in result["findings"]}
    assert {"CG-POL-001", "CG-POL-002", "CG-POL-003", "CG-POL-004"} <= ids


def test_identical_configs_have_no_diff_findings_and_report_assumptions():
    cfg = config([rule()])
    result = analyze(AnalyzeRequest(before=cfg, after=cfg))
    assert result["changes"]["changed"] == []
    assert result["findings"] == []
    assert result["rules_version"] == "1.0.0"
    json.dumps(result)


def test_existing_allow_default_is_flagged_even_without_a_change():
    cfg = config([rule()], default="allow")
    result = analyze(AnalyzeRequest(before=cfg, after=cfg))
    finding = next(f for f in result["findings"] if f["title"] == "Default policy allows unmatched traffic")
    assert finding["severity"] == "high"


def test_zero_prefix_ranges_and_wildcard_admin_ports_are_flagged():
    cfg = config(
        [
            rule("open-v4", source="0.0.0.0/0", destination="0.0.0.0/0", port="*"),
        ]
    )
    result = analyze(AnalyzeRequest(before=config([]), after=cfg))
    titles = {finding["title"] for finding in result["findings"]}
    assert "Unrestricted network access" in titles
    assert "Administrative port is allowed" in titles
