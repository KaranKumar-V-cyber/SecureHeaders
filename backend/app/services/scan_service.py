"""Scan service for analyzing websites."""

import asyncio
import httpx
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse
from sqlalchemy.orm import Session

from app.models import Scan
from app.schemas import AnalyzeRequest, Finding, SeverityCount
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.security.ssrf import validate_ssrf
from app.security.redaction import DataRedactor
from app.config import settings

BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


class ScanService:
    """Service for performing security scans."""
    
    @staticmethod
    async def analyze_website(
        request: AnalyzeRequest,
        db: Session
    ) -> Tuple[Scan, Optional[str]]:
        scan_id = str(uuid.uuid4())
        
        scan = Scan(
            id=scan_id,
            target=request.target,
            status="pending",
            response_headers={},
            findings=[],
            severity_counts={}
        )
        
        try:
            if not request.authorization_confirmed:
                error_msg = "Authorization not confirmed"
                scan.status = "failed"
                scan.error_message = error_msg
                db.add(scan)
                db.commit()
                return scan, error_msg
            
            try:
                validate_ssrf(request.target)
            except ValueError as e:
                error_msg = f"Target validation failed: {str(e)}"
                scan.status = "failed"
                scan.error_message = error_msg
                db.add(scan)
                db.commit()
                return scan, error_msg
            
            target_url = request.target.strip()
            if not target_url.startswith(("http://", "https://")):
                target_url = f"https://{target_url}"
            
            headers_result, error = await ScanService._fetch_headers(target_url)
            
            if error:
                scan.status = "failed"
                scan.error_message = error
                db.add(scan)
                db.commit()
                return scan, error
            
            response_headers = headers_result.get("headers", {})
            http_status = headers_result.get("status", None)
            response_time_ms = headers_result.get("response_time_ms", 0)
            redirect_count = headers_result.get("redirect_count", 0)
            final_url = headers_result.get("final_url", target_url)
            server_info = response_headers.get("server", "Not exposed")
            content_type = response_headers.get("content-type", "Unknown")
            
            redacted_headers = DataRedactor.redact_headers(response_headers)
            
            analyzer = HeaderAnalyzer(response_headers)
            findings, severity_counts, security_score = analyzer.analyze()
            
            scan.status = "completed"
            scan.final_url = final_url
            scan.http_status = http_status
            scan.response_time_ms = response_time_ms
            scan.redirect_count = redirect_count
            scan.server_info = server_info if server_info != "Not exposed" else None
            scan.content_type = content_type
            scan.security_score = security_score
            scan.completed_at = datetime.now(timezone.utc)
            scan.response_headers = redacted_headers
            scan.findings = [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "description": f.description,
                    "evidence": f.evidence,
                    "impact": f.impact,
                    "remediation": f.remediation,
                    "reference": f.reference,
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                }
                for f in findings
            ]
            scan.severity_counts = {
                "CRITICAL": severity_counts.CRITICAL,
                "HIGH": severity_counts.HIGH,
                "MEDIUM": severity_counts.MEDIUM,
                "LOW": severity_counts.LOW,
                "INFO": severity_counts.INFO,
            }
            
            db.add(scan)
            db.commit()
            db.refresh(scan)
            
            return scan, None
        
        except Exception as e:
            db.rollback()
            scan.status = "failed"
            scan.error_message = f"Unexpected error: {str(e)}"
            try:
                db.add(scan)
                db.commit()
            except Exception:
                db.rollback()
            return scan, str(e)
    
    @staticmethod
    async def _fetch_headers(url: str) -> Tuple[Dict[str, Any], Optional[str]]:
        try:
            req_headers = {
                "User-Agent": BROWSER_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1"
            }
            async with httpx.AsyncClient(
                follow_redirects=True,
                max_redirects=settings.ssrf_max_redirects,
                timeout=settings.ssrf_timeout,
                verify=True
            ) as client:
                response = await client.get(url, headers=req_headers)
                
                headers = dict(response.headers)
                response_time_ms = int(response.elapsed.total_seconds() * 1000)
                
                return {
                    "headers": headers,
                    "status": response.status_code,
                    "response_time_ms": response_time_ms,
                    "redirect_count": len(response.history),
                    "final_url": str(response.url),
                }, None
        
        except httpx.ConnectError as e:
            return {}, f"Connection error: {str(e)}"
        except httpx.TimeoutException as e:
            return {}, f"Request timeout: {str(e)}"
        except httpx.HTTPError as e:
            return {}, f"HTTP error: {str(e)}"
        except Exception as e:
            return {}, f"Error fetching headers: {str(e)}"
    
    @staticmethod
    def get_scan(scan_id: str, db: Session) -> Optional[Scan]:
        return db.query(Scan).filter(Scan.id == scan_id).first()
    
    @staticmethod
    def list_scans(
        db: Session,
        limit: int = 20,
        offset: int = 0,
        search: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Tuple[int, list[Scan]]:
        query = db.query(Scan)
        if search:
            query = query.filter(Scan.target.ilike(f"%{search}%"))
        if status:
            query = query.filter(Scan.status == status)
        query = query.order_by(Scan.created_at.desc())
        total_count = query.count()
        scans = query.offset(offset).limit(limit).all()
        return total_count, scans
    
    @staticmethod
    def delete_scan(scan_id: str, db: Session) -> bool:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            db.delete(scan)
            db.commit()
            return True
        return False
