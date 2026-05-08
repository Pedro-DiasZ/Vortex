from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class TextContentRequest(RequestModel):
    content: str = Field(..., min_length=1, max_length=80000)


class AIHeaderRequest(RequestModel):
    content: str = Field(..., min_length=1, max_length=80000)


class AILogsRequest(RequestModel):
    content: str = Field(..., min_length=1, max_length=80000)


class AIEmailHealthRequest(RequestModel):
    domain: str = Field(..., min_length=3, max_length=253)


class AIReputationRequest(RequestModel):
    content: str = Field(..., min_length=1, max_length=80000)


class EmailLogAnalysisRequest(RequestModel):
    content: str = Field(..., min_length=1, max_length=20000)


class HibpPasswordRequest(RequestModel):
    password: str = Field(..., min_length=1, max_length=256)


class DiagnoseRequest(RequestModel):
    smtp_error: str | None = Field(default=None, max_length=20000)
    log: str | None = Field(default=None, max_length=20000)
    content: str | None = Field(default=None, max_length=20000)
    domain: str | None = Field(default=None, max_length=253)
    email_account: str | None = Field(default=None, max_length=255)


class SmtpAnalyzeRequest(RequestModel):
    error: str | None = Field(default=None, max_length=20000)
    content: str | None = Field(default=None, max_length=20000)


class ResponseGenerateRequest(RequestModel):
    problem_type: str = Field(default="", max_length=80)
    tone: str = Field(default="", max_length=80)
    customer_name: str = Field(default="", max_length=120)
    domain: str = Field(default="", max_length=255)
    email_account: str = Field(default="", max_length=255)
    error_found: str = Field(default="", max_length=2000)
    action_done: str = Field(default="", max_length=2000)
    next_step: str = Field(default="", max_length=2000)


class DomainHealthRequest(RequestModel):
    domain: str = Field(..., min_length=3, max_length=253)
    selector: str = Field(default="", max_length=80)


class MarkdownRenderRequest(RequestModel):
    markdown: str | None = Field(default=None, max_length=100000)
    content: str | None = Field(default=None, max_length=100000)


class PromptGenerateRequest(RequestModel):
    context: str | None = Field(default=None, max_length=20000)
    content: str | None = Field(default=None, max_length=20000)
    objective: str | None = Field(default=None, max_length=2000)
    tone: str | None = Field(default=None, max_length=80)
    output_type: str | None = Field(default=None, max_length=120)
    detail_level: str | None = Field(default=None, max_length=120)
    output_format: str | None = Field(default=None, max_length=120)
    avoid: str | None = Field(default=None, max_length=4000)
    extra_info: str | None = Field(default=None, max_length=4000)
    target_audience: str | None = Field(default=None, max_length=120)
    ai_model: str | None = Field(default=None, max_length=120)
    language: str | None = Field(default=None, max_length=80)
    expected_size: str | None = Field(default=None, max_length=120)
    ask_questions: str | None = Field(default=None, max_length=160)
    required_keywords: str | None = Field(default=None, max_length=1000)
    include_examples: bool | None = None
    include_quality_criteria: bool | None = None
    include_persona: bool | None = None
    include_technical_context: bool | None = None


class MigrationReviewSummaryRequest(RequestModel):
    content: str | None = Field(default=None, max_length=50000)
    accounts: list[dict[str, Any]] | None = None
    domain: str | None = Field(default=None, max_length=253)
