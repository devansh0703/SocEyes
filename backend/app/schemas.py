from __future__ import annotations

from pydantic import BaseModel, Field


class QueryRequest(BaseModel):
    query: str = Field(min_length=1)
    limit: int = Field(default=10, ge=1, le=50)
    engines: list[str] = Field(default_factory=list)
    start: str | None = None
    end: str | None = None


class PolicyUpdateRequest(BaseModel):
    auto_execute: bool
    engines: dict[str, bool]
    allow_manual_execute: bool = True


class ManualResponseRequest(BaseModel):
    alert_index: str | None = None
    alert_id: str | None = None
    engine: str
    rule_id: str = ""
    technique_id: str = ""
    mitre_ids: list[str] = Field(default_factory=list)
    source_ip: str = ""
    destination_ip: str = ""
    username: str = ""
    message: str = ""
    severity: str = ""


class ResponsePreviewRequest(BaseModel):
    engine: str = ""
    rule_id: str = ""
    technique_id: str = ""
    mitre_ids: list[str] = Field(default_factory=list)
    source_ip: str = ""
    destination_ip: str = ""
    username: str = ""
    message: str = ""
    severity: str = ""
    include_llm: bool = True


class ChatRequest(BaseModel):
    message: str = Field(min_length=1)
    start: str | None = None
    end: str | None = None
    run_id: str | None = None
    detailed: bool = True


class RunStartRequest(BaseModel):
    name: str = ""
    note: str = ""


class RunSaveRequest(BaseModel):
    name: str = ""
    note: str = ""
