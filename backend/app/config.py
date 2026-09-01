import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings from environment variables."""
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")
    
    # Database
    database_url: str = "sqlite:///./scan_history.db"
    
    # API Configuration
    api_title: str = "HeaderSentinel API"
    api_version: str = "1.0.0"
    api_description: str = "Web Security Header Analyzer"
    
    # CORS
    backend_cors_origins: list[str] = ["http://localhost:3000", "http://localhost:8000"]
    
    # Rate Limiting
    rate_limit_calls: int = 100
    rate_limit_period: int = 60  # seconds
    
    # SSRF Protection
    ssrf_allow_private: bool = False
    ssrf_timeout: int = 10
    ssrf_max_redirects: int = 5
    ssrf_max_response_size: int = 10 * 1024 * 1024  # 10MB
    
    # SSRF Allowlist (comma-separated hostnames for internal testing)
    ssrf_allowlist: str = ""
    
    # Security
    secret_key: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    
    # Logging
    log_level: str = "INFO"


settings = Settings()
