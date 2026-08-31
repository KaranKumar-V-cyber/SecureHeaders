"""API routes for HeaderSentinel."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional

from app.database import get_db
from app.schemas import (
    AnalyzeRequest, ScanResponse, ScanListResponse, ScanListItem, ErrorResponse
)
from app.services.scan_service import ScanService
from app.models import Scan
from app.config import settings


router = APIRouter(prefix="/api/v1", tags=["scans"])


@router.post("/analyze", response_model=ScanResponse, summary="Analyze a website")
async def analyze_website(
    request: AnalyzeRequest,
    db: Session = Depends(get_db)
):
    """
    Analyze HTTP response headers of a website.
    
    Requires authorization confirmation to prevent unauthorized testing.
    """
    scan, error = await ScanService.analyze_website(request, db)
    
    if error and scan.status == "failed":
        raise HTTPException(status_code=400, detail=error)
    
    return _scan_to_response(scan)


@router.get("/scans/{scan_id}", response_model=ScanResponse, summary="Get scan details")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve details of a specific scan."""
    scan = ScanService.get_scan(scan_id, db)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return _scan_to_response(scan)


@router.get("/scans", response_model=ScanListResponse, summary="List scans")
def list_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    List all scans with optional filtering.
    
    Supports:
    - `search`: Search by target hostname
    - `status`: Filter by scan status (pending, completed, failed)
    - `severity`: Filter by finding severity
    """
    total, scans = ScanService.list_scans(
        db=db,
        limit=limit,
        offset=offset,
        search=search,
        status=status,
        severity=severity
    )
    
    items = [
        ScanListItem(
            scan_id=scan.id,
            target=scan.target,
            status=scan.status,
            security_score=scan.security_score,
            severity_counts=scan.severity_counts or {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            },
            created_at=scan.created_at
        )
        for scan in scans
    ]
    
    return ScanListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=items
    )


@router.delete("/scans/{scan_id}", summary="Delete a scan")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Delete a scan from history."""
    success = ScanService.delete_scan(scan_id, db)
    
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {"message": "Scan deleted successfully"}


@router.get("/reports/{scan_id}/json", summary="Export scan as JSON")
def export_json(scan_id: str, db: Session = Depends(get_db)):
    """Export scan report as JSON."""
    scan = ScanService.get_scan(scan_id, db)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return _scan_to_response(scan)


@router.get("/reports/{scan_id}/markdown", summary="Export scan as Markdown")
def export_markdown(scan_id: str, db: Session = Depends(get_db)):
    """Export scan report as Markdown."""
    scan = ScanService.get_scan(scan_id, db)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    markdown = _generate_markdown_report(scan)
    
    return {
        "format": "markdown",
        "content": markdown,
        "filename": f"report_{scan_id[:8]}.md"
    }


@router.get("/reports/{scan_id}/pdf", summary="Export scan as PDF")
def export_pdf(scan_id: str, db: Session = Depends(get_db)):
    """Export scan report as PDF."""
    scan = ScanService.get_scan(scan_id, db)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # PDF generation would be implemented here
    return {
        "message": "PDF export functionality coming soon",
        "scan_id": scan_id
    }


@router.get("/health", summary="Health check")
def health_check():
    """Check API health status."""
    return {
        "status": "healthy",
        "version": settings.api_version,
        "database": "connected"
    }


def _scan_to_response(scan: Scan) -> ScanResponse:
    """Convert Scan model to API response."""
    findings = []
    if scan.findings:
        for f in scan.findings:
            findings.append(f)  # Already in the correct format
    
    return ScanResponse(
        scan_id=scan.id,
        target=scan.target,
        final_url=scan.final_url,
        status=scan.status,
        security_score=scan.security_score,
        http_status=scan.http_status,
        response_time_ms=scan.response_time_ms,
        redirect_count=scan.redirect_count,
        server_info=scan.server_info,
        content_type=scan.content_type,
        response_headers=scan.response_headers or {},
        findings=findings,
        severity_counts=scan.severity_counts or {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        },
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message
    )


def _generate_markdown_report(scan: Scan) -> str:
    """Generate Markdown report."""
    markdown = f"""# Security Header Analysis Report

## Executive Summary
- **Target**: {scan.target}
- **Final URL**: {scan.final_url}
- **Security Score**: {scan.security_score}/100
- **Scan Date**: {scan.created_at}
- **HTTP Status**: {scan.http_status}
- **Response Time**: {scan.response_time_ms}ms

## Findings Summary
- **Critical**: {scan.severity_counts.get('CRITICAL', 0)}
- **High**: {scan.severity_counts.get('HIGH', 0)}
- **Medium**: {scan.severity_counts.get('MEDIUM', 0)}
- **Low**: {scan.severity_counts.get('LOW', 0)}
- **Info**: {scan.severity_counts.get('INFO', 0)}

## Response Headers
```
"""
    
    for header, value in (scan.response_headers or {}).items():
        markdown += f"{header}: {value}\n"
    
    markdown += """```

## Detailed Findings
"""
    
    if scan.findings:
        for finding in scan.findings:
            markdown += f"""
### {finding['title']}
- **Severity**: {finding['severity']}
- **Category**: {finding['category']}
- **Description**: {finding['description']}
- **Impact**: {finding['impact']}
- **Remediation**: {finding['remediation']}

"""
    
    markdown += """
---
*Generated by HeaderSentinel - Web Security Header Analyzer*
"""
    
    return markdown
