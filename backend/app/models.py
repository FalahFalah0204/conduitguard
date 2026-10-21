"""Strict, documented input and output models for the ConduitGuard API."""

from __future__ import annotations

import ipaddress
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

RuleId = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")]
Address = Annotated[str, Field(min_length=1, max_length=64)]
Port = int | Literal["*"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)


class Rule(StrictModel):
    id: RuleId
    source: Address = Field(description="IPv4/IPv6 address, CIDR network, or * for any source.")
    destination: Address = Field(description="IPv4/IPv6 address, CIDR network, or * for any destination.")
    protocol: Literal["tcp", "udp", "icmp", "any"]
    port: Port = Field(default="*", description="TCP/UDP port number or *; ICMP requires *.")
    action: Literal["allow", "deny"]
    priority: int = Field(default=100, ge=0, le=65535, description="Lower values are evaluated first.")
    description: str | None = Field(default=None, max_length=300)

    @field_validator("source", "destination")
    @classmethod
    def valid_address(cls, value: str) -> str:
        if value == "*":
            return value
        try:
            if "/" in value:
                ipaddress.ip_network(value, strict=False)
            else:
                ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("must be *, an IP address, or a CIDR network") from exc
        return value

    @field_validator("port")
    @classmethod
    def valid_port(cls, value: Port) -> Port:
        if value != "*" and not 1 <= value <= 65535:
            raise ValueError("port must be * or an integer from 1 through 65535")
        return value

    @model_validator(mode="after")
    def icmp_port_is_wildcard(self) -> Rule:
        if self.protocol == "icmp" and self.port != "*":
            raise ValueError("ICMP rules must use port *")
        return self


class FirewallConfig(StrictModel):
    default_policy: Literal["allow", "deny"] = "deny"
    rules: list[Rule] = Field(max_length=500)

    @model_validator(mode="after")
    def unique_ids(self) -> FirewallConfig:
        ids = [rule.id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule IDs must be unique")
        return self


class ConnectionProbe(StrictModel):
    source: Address
    destination: Address
    protocol: Literal["tcp", "udp", "icmp"]
    port: int | None = Field(default=None, ge=1, le=65535)
    label: str | None = Field(default=None, max_length=120)

    @field_validator("source", "destination")
    @classmethod
    def valid_probe_address(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("connection endpoints must be IP addresses") from exc
        return value

    @model_validator(mode="after")
    def port_matches_protocol(self) -> ConnectionProbe:
        if self.protocol in {"tcp", "udp"} and self.port is None:
            raise ValueError("TCP and UDP probes require a port")
        if self.protocol == "icmp" and self.port is not None:
            raise ValueError("ICMP probes do not have a port")
        return self


class AnalyzeRequest(StrictModel):
    before: FirewallConfig
    after: FirewallConfig
    probes: list[ConnectionProbe] = Field(default_factory=list, max_length=100)


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: list[dict[str, object]] | None = None


def parse_config_json(raw: str) -> FirewallConfig:
    """Parse JSON using Pydantic's strict schema, with no dynamic evaluation."""
    return FirewallConfig.model_validate_json(raw)
