from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["info", "low", "medium", "high", "critical"]


class PacketRecord(BaseModel):
    id: int = 0
    timestamp: float
    captured_at: str
    src: str = "unknown"
    dst: str = "unknown"
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "OTHER"
    transport: str = "OTHER"
    length: int = 0
    direction: str = "unknown"
    info: str = ""
    tcp_flags: str | None = None
    dns_query: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    suspicious: bool = False
    severity: Severity | None = None
    alert_ids: list[int] = Field(default_factory=list)


class AlertRecord(BaseModel):
    id: int = 0
    timestamp: float
    detected_at: str
    type: str
    title: str
    description: str
    severity: Severity
    source: str
    destination: str | None = None
    packet_id: int
    evidence: dict[str, str | int | float] = Field(default_factory=dict)
    recommendation: str


class StartCaptureRequest(BaseModel):
    mode: Literal["demo", "live"] = "demo"
    interface: str | None = None


class AdvisorMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=4000)


class AdvisorRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    alert_id: int | None = None
    history: list[AdvisorMessage] = Field(default_factory=list, max_length=12)


class AdvisorResponse(BaseModel):
    answer: str
    provider: Literal["ollama", "rules"]
    model: str | None = None
    notice: str | None = None


class AdvisorStatus(BaseModel):
    enabled: bool
    state: Literal["ready", "disabled", "unreachable", "model_missing", "error"]
    provider: Literal["ollama", "rules"]
    model: str
    message: str
