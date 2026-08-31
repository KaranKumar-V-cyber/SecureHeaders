from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime
from typing import Optional, Dict, Any, List


class AnalyzeRequest(BaseModel):
    """Request model for analyzing a website."""
    target: str = Field(..., min_length=1, max_length=2048)
    authorization_confirmed: bool = Field(..., description="User confirms authorization to test target")


class SeverityCount(BaseModel):
    """Count of findings by severity."""
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFO: int = 0


class Finding(BaseModel):
    """Security finding."""
    id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    description: str
    evidence: Dict[str, Any]
    impact: str
    remediation: str
    reference: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None


class ScanResponse(BaseModel):
    """Response model for a scan."""
    scan_id: str
    target: str
    final_url: Optional[str]
    status: str
    security_score: Optional[float]
    http_status: Optional[int]
    response_time_ms: Optional[int]
    redirect_count: int
    server_info: Optional[str]
    content_type: Optional[str]
    response_headers: Dict[str, Any]
    findings: List[Finding]
    severity_counts: SeverityCount
    created_at: datetime
    completed_at: Optional[datetime]
    error_message: Optional[str]


class ScanListItem(BaseModel):
    """Minimal scan information for list view."""
    scan_id: str
    target: str
    status: str
    security_score: Optional[float]
    severity_counts: SeverityCount
    created_at: datetime


class ScanListResponse(BaseModel):
    """Response for listing scans."""
    total: int
    limit: int
    offset: int
    items: List[ScanListItem]


class SecurityScore(BaseModel):
    """Security score breakdown."""
    overall_score: float
    severity_breakdown: SeverityCount
    deductions: List[Dict[str, Any]]
    explanation: str


class ReportRequest(BaseModel):
    """Request for generating a report."""
    format: str = Field(..., regex="^(json|markdown|pdf)$")


class ErrorResponse(BaseModel):
    """Error response model."""
    detail: str
    error_code: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    database: str
