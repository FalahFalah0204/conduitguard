"""Order-independent diff, explicit security policies, and offline simulation."""

from __future__ import annotations

import ipaddress
from typing import Any

from .models import AnalyzeRequest, FirewallConfig, Rule

RULES_VERSION = "1.0.0"
SUPPORTED_SEMANTICS = "First match: ascending priority, then lexicographic rule ID. * matches any address/protocol/port. CIDR uses address membership. No matching rule uses default_policy."


def _rule_dict(rule: Rule) -> dict[str, Any]:
    return rule.model_dump(mode="json")


def diff_configs(before: FirewallConfig, after: FirewallConfig) -> dict[str, Any]:
    old = {r.id: r for r in before.rules}
    new = {r.id: r for r in after.rules}
    added = [_rule_dict(new[k]) for k in sorted(new.keys() - old.keys())]
    removed = [_rule_dict(old[k]) for k in sorted(old.keys() - new.keys())]
    changed = []
    unchanged = []
    for key in sorted(old.keys() & new.keys()):
        if _rule_dict(old[key]) == _rule_dict(new[key]):
            unchanged.append(key)
        else:
            changed.append({"id": key, "before": _rule_dict(old[key]), "after": _rule_dict(new[key])})
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
        "default_policy": {"before": before.default_policy, "after": after.default_policy}
        if before.default_policy != after.default_policy
        else None,
    }


def _network(value: str):
    if value == "*":
        return None
    if "/" not in value:
        return ipaddress.ip_network(f"{value}/{ipaddress.ip_address(value).max_prefixlen}")
    return ipaddress.ip_network(value, strict=False)


def _is_wildcard_address(value: str) -> bool:
    return value == "*" or (value != "*" and _network(value).prefixlen == 0)


def _address_broadened(old: str, new: str) -> bool:
    if old == new:
        return False
    if new == "*":
        return old != "*"
    if old == "*":
        return False
    old_net, new_net = _network(old), _network(new)
    return old_net.version == new_net.version and old_net.subnet_of(new_net) and old_net != new_net


def _protocol_broadened(old: str, new: str) -> bool:
    return old != new and new == "any"


def _widened(old: Rule, new: Rule) -> bool:
    if old.action == "deny" and new.action == "allow":
        return True
    if old.action != "allow" or new.action != "allow":
        return False
    return (
        _address_broadened(old.source, new.source)
        or _address_broadened(old.destination, new.destination)
        or _protocol_broadened(old.protocol, new.protocol)
        or (old.port != "*" and new.port == "*")
    )


def _matches_address(selector: str, address: str) -> bool:
    if selector == "*":
        return True
    ip = ipaddress.ip_address(address)
    return ip in _network(selector)


def _matches(rule: Rule, probe: Any) -> bool:
    return (
        _matches_address(rule.source, probe.source)
        and _matches_address(rule.destination, probe.destination)
        and (rule.protocol == "any" or rule.protocol == probe.protocol)
        and (rule.port == "*" or rule.port == probe.port)
    )


def simulate(config: FirewallConfig, probes: list[Any]) -> list[dict[str, Any]]:
    ordered = sorted(config.rules, key=lambda r: (r.priority, r.id))
    results = []
    for probe in probes:
        hit = next((rule for rule in ordered if _matches(rule, probe)), None)
        result = {
            "probe": probe.model_dump(mode="json"),
            "decision": hit.action if hit else config.default_policy,
            "matched_rule_id": hit.id if hit else None,
            "reason": f"Matched rule {hit.id} at priority {hit.priority}."
            if hit
            else f"No rule matched; default policy is {config.default_policy}.",
        }
        results.append(result)
    return results


def _overlap_address(left: str, right: str) -> bool:
    if left == "*" or right == "*":
        return True
    a, b = _network(left), _network(right)
    return a.version == b.version and a.overlaps(b)


def _overlap_protocol(left: str, right: str) -> bool:
    return left == "any" or right == "any" or left == right


def _overlap_port(left: Rule, right: Rule) -> bool:
    return left.port == "*" or right.port == "*" or left.port == right.port


def findings(before: FirewallConfig, after: FirewallConfig, diff: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def add(
        rule_id: str, severity: str, code: str, title: str, evidence: dict[str, Any], explanation: str, mitigation: str
    ):
        out.append(
            {
                "id": code,
                "severity": severity,
                "title": title,
                "rule_ids": [rule_id] if rule_id else [],
                "evidence": evidence,
                "explanation": explanation,
                "mitigation": mitigation,
            }
        )

    by_id_before = {r.id: r for r in before.rules}
    for rule in after.rules:
        if rule.action == "allow" and _is_wildcard_address(rule.source) and _is_wildcard_address(rule.destination):
            add(
                rule.id,
                "high",
                "CG-POL-001",
                "Unrestricted network access",
                {"source": rule.source, "destination": rule.destination, "action": rule.action},
                "This allow rule accepts traffic from every source to every destination.",
                "Restrict source and destination to the smallest required CIDR ranges.",
            )
        if (
            rule.action == "allow"
            and rule.protocol in {"tcp", "udp", "any"}
            and (rule.port in {22, 23, 3389, 5900} or rule.port == "*")
        ):
            add(
                rule.id,
                "high",
                "CG-POL-002",
                "Administrative port is allowed",
                {"protocol": rule.protocol, "port": rule.port, "source": rule.source},
                "SSH, Telnet, RDP, or VNC is reachable through an allow rule. Telnet is especially unsafe in clear text.",
                "Limit administrative access to a dedicated management CIDR and prefer encrypted protocols.",
            )
        old = by_id_before.get(rule.id)
        if old and _widened(old, rule):
            add(
                rule.id,
                "medium",
                "CG-POL-004",
                "Rule expands allowed access",
                {"before": _rule_dict(old), "after": _rule_dict(rule)},
                "The updated allow rule matches a wider address, protocol, port, or action scope.",
                "Review the expanded scope and narrow the match fields if it is not required.",
            )
    for rule in diff["added"]:
        if rule["action"] == "allow":
            add(
                rule["id"],
                "medium",
                "CG-POL-004",
                "New allow rule expands access",
                rule,
                "Adding an allow rule can grant connectivity that did not exist before.",
                "Confirm the new access is required and restrict its source, destination, protocol, and port.",
            )
    if before.default_policy == "allow" and after.default_policy == "allow":
        add(
            "",
            "high",
            "CG-POL-001",
            "Default policy allows unmatched traffic",
            {"default_policy": after.default_policy},
            "Any connection not matched by a rule will be permitted.",
            "Use a deny-by-default policy and explicitly allow required traffic.",
        )
    if before.default_policy == "deny" and after.default_policy == "allow":
        add(
            "",
            "critical",
            "CG-POL-004",
            "Default policy changes to allow",
            {"before": "deny", "after": "allow"},
            "Unmatched traffic will now be permitted.",
            "Restore a deny-by-default policy and add explicit required allow rules.",
        )
    for i, left in enumerate(after.rules):
        for right in after.rules[i + 1 :]:
            if (
                left.priority == right.priority
                and left.action != right.action
                and _overlap_address(left.source, right.source)
                and _overlap_address(left.destination, right.destination)
                and _overlap_protocol(left.protocol, right.protocol)
                and _overlap_port(left, right)
            ):
                add(
                    left.id,
                    "medium",
                    "CG-POL-003",
                    "Conflicting rules have equal priority",
                    {
                        "rule_ids": [left.id, right.id],
                        "priority": left.priority,
                        "actions": [left.action, right.action],
                    },
                    "Both rules can match the same connection but make opposite decisions. Lexicographic rule ID breaks the tie.",
                    "Assign distinct priorities or make the match scopes disjoint.",
                )
    return out


def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    changes = diff_configs(request.before, request.after)
    return {
        "changes": changes,
        "findings": findings(request.before, request.after, changes),
        "simulation": {
            "before": simulate(request.before, request.probes),
            "after": simulate(request.after, request.probes),
        },
        "recommendations": [f["mitigation"] for f in findings(request.before, request.after, changes)],
        "rules_version": RULES_VERSION,
        "assumptions": [
            SUPPORTED_SEMANTICS,
            "Rules are compared by ID; input order does not affect diff or evaluation.",
            "Administrative ports checked: 22, 23, 3389, 5900.",
            "Simulation is offline and evaluates only supplied probes.",
        ],
        "limitations": [
            "This is a documented generic model, not a vendor configuration parser.",
            "It does not inspect routing, NAT, stateful sessions, interfaces, or actual network reachability.",
            "Policy findings are heuristics and do not detect every vulnerability.",
        ],
    }
