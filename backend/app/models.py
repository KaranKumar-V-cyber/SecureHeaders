from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, JSON, Float, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Scan(Base):
    """Database model for security scans."""
    
    __tablename__ = "scans"
    
    id = Column(String, primary_key=True, index=True)
    target = Column(String, index=True)
    final_url = Column(String, nullable=True)
    status = Column(String, default="pending")  # pending, completed, failed
    security_score = Column(Float, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Response Information
    http_status = Column(Integer, nullable=True)
    response_time_ms = Column(Integer, nullable=True)
    redirect_count = Column(Integer, default=0)
    server_info = Column(String, nullable=True)
    content_type = Column(String, nullable=True)
    
    # Analysis Results
    response_headers = Column(JSON)  # Stored headers
    findings = Column(JSON)  # Array of findings
    severity_counts = Column(JSON)  # {CRITICAL: 0, HIGH: 1, ...}
    
    # Error Information
    error_message = Column(Text, nullable=True)
    
    # Metadata
    user_agent = Column(String, nullable=True)
    
    def __repr__(self):
        return f"<Scan(id={self.id}, target={self.target}, score={self.security_score})>"
