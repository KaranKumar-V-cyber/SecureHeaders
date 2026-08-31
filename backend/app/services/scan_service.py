"""Scan service for analyzing websites."""

import asyncio
import httpx
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse
from sqlalchemy.orm import Session

from app.models import Scan
from app.schemas import AnalyzeRequest, Finding, SeverityCount
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.security.ssrf import validate_ssrf
from app.security.redaction import DataRedactor
from app.config import settings


class ScanService:
    """Service for performing security scans."""
    
    @staticmethod
    async def analyze_website(
        request: AnalyzeRequest,
        db: Session
    ) -> Tuple[Scan, Optional[str]]:
        """
        Analyze a website's HTTP headers.
        
        Returns:
            Tuple of (scan_model, error_message)
        """
        scan_id = str(uuid.uuid4())
        
        # Create scan record
        scan = Scan(
            id=scan_id,
            target=request.target,
            status="pending",
            response_headers={},
            findings=[],
            severity_counts={}
        )
        
        try:
            # Validate authorization
            if not request.authorization_confirmed:
                error_msg = "Authorization not confirmed"
                scan.status = "failed"
                scan.error_message = error_msg
                db.add(scan)
                db.commit()
                return scan, error_msg
            
            # Validate SSRF
            try:
                validate_ssrf(request.target)
            except ValueError as e:
                error_msg = f"Target validation failed: {str(e)}"
                scan.status = "failed"
                scan.error_message = error_msg
                db.add(scan)
                db.commit()
                return scan, error_msg
            
            # Normalize URL
            target_url = request.target
            if not target_url.startswith(("http://", "https://")):
                target_url = f"https://{target_url}"
            
            # Fetch headers
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
            
            # Redact sensitive headers
            redacted_headers = DataRedactor.redact_headers(response_headers)
            
            # Analyze headers
            analyzer = HeaderAnalyzer(response_headers)
            findings, severity_counts, security_score = analyzer.analyze()
            
            # Update scan
            scan.status = "completed"
            scan.final_url = final_url
            scan.http_status = http_status
            scan.response_time_ms = response_time_ms
            scan.redirect_count = redirect_count
            scan.server_info = server_info if server_info != "Not exposed" else None
            scan.content_type = content_type
            scan.security_score = security_score
            scan.completed_at = datetime.utcnow()
            
            # Convert to JSON-serializable format
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
            scan.status = "failed"
            scan.error_message = f"Unexpected error: {str(e)}"
            try:
                db.add(scan)
                db.commit()
            except:
                pass
            return scan, str(e)
    
    @staticmethod
    async def _fetch_headers(url: str) -> Tuple[Dict[str, Any], Optional[str]]:
        """
        Fetch HTTP headers from a URL.
        
        Returns:
            Tuple of (headers_dict, error_message)
        """
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=settings.ssrf_timeout
            ) as client:
                response = await client.head(url)
                
                # Fallback to GET if HEAD is not allowed
                if response.status_code in (405, 501):
                    response = await client.get(url)
                
                headers = dict(response.headers)
                
                # Get response time (approximate)
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
        """Get a scan by ID."""
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
        """
        List scans with filtering.
        
        Returns:
            Tuple of (total_count, scans)
        """
        query = db.query(Scan)
        
        # Search by target
        if search:
            query = query.filter(Scan.target.ilike(f"%{search}%"))
        
        # Filter by status
        if status:
            query = query.filter(Scan.status == status)
        
        # Filter by severity (check if severity_counts contains any findings of that level)
        if severity:
            # This is a simplified approach - for production, consider a dedicated severity column
            pass
        
        # Order by created_at descending
        query = query.order_by(Scan.created_at.desc())
        
        total_count = query.count()
        scans = query.offset(offset).limit(limit).all()
        
        return total_count, scans
    
    @staticmethod
    def delete_scan(scan_id: str, db: Session) -> bool:
        """Delete a scan."""
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            db.delete(scan)
            db.commit()
            return True
        return False
