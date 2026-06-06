"""
AgentOps Security Mesh — Pydantic Settings Configuration.

All configuration is loaded from environment variables.
Never hardcode secrets — always use .env or container env injection.
"""

from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central configuration object for the AgentOps Security Mesh backend.

    Loaded from environment variables with .env file fallback.
    All secrets (keys, passwords) are required in production.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─────────────────────────────────────────────────────────────
    # Application
    # ─────────────────────────────────────────────────────────────
    env: str = Field(default="development", description="Runtime environment")
    secret_key: str = Field(
        default="dev-secret-key-change-in-production-min-32-chars!!",
        description="JWT signing secret — min 32 chars",
    )
    api_key: str = Field(
        default="dev-api-key",
        description="Bearer token for API authentication",
    )
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000",
        description="Comma-separated allowed CORS origins",
    )

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse comma-separated CORS origins into a list."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    # ─────────────────────────────────────────────────────────────
    # Azure OpenAI
    # ─────────────────────────────────────────────────────────────
    azure_openai_endpoint: str = Field(
        default="",
        description="Azure OpenAI resource endpoint URL",
    )
    azure_openai_key: str = Field(
        default="",
        description="Azure OpenAI API key",
    )
    azure_openai_deployment: str = Field(
        default="gpt-4o",
        description="Azure OpenAI deployment name",
    )
    azure_openai_api_version: str = Field(
        default="2024-08-01-preview",
        description="Azure OpenAI API version",
    )

    # ─────────────────────────────────────────────────────────────
    # GitHub Models (Fallback LLM)
    # ─────────────────────────────────────────────────────────────
    github_token: str = Field(
        default="",
        description="GitHub PAT with models:read scope",
    )
    github_models_endpoint: str = Field(
        default="https://models.inference.ai.azure.com",
        description="GitHub Models inference endpoint",
    )
    github_models_model: str = Field(
        default="gpt-4o",
        description="Model name for GitHub Models",
    )

    # ─────────────────────────────────────────────────────────────
    # Phi-3 Local Inference
    # ─────────────────────────────────────────────────────────────
    phi3_enabled: bool = Field(
        default=False,
        description="Enable local Phi-3 inference via Ollama",
    )
    phi3_endpoint: str = Field(
        default="http://localhost:11434",
        description="Ollama API endpoint for Phi-3",
    )
    phi3_model: str = Field(
        default="phi3",
        description="Phi-3 model name in Ollama",
    )

    # ─────────────────────────────────────────────────────────────
    # Redis — Per-agent memory + pub/sub event bus
    # ─────────────────────────────────────────────────────────────
    redis_url: str = Field(
        default="redis://:meshredis@localhost:6379/0",
        description="Full Redis connection URL",
    )
    redis_password: str = Field(
        default="meshredis",
        description="Redis AUTH password",
    )
    redis_default_ttl: int = Field(
        default=3600,
        ge=60,
        description="Default TTL for agent memory keys (seconds)",
    )
    redis_event_ttl: int = Field(
        default=86400,
        ge=3600,
        description="TTL for security event log entries (seconds)",
    )

    # ─────────────────────────────────────────────────────────────
    # Neo4j — Trust graph
    # ─────────────────────────────────────────────────────────────
    neo4j_uri: str = Field(
        default="bolt://localhost:7687",
        description="Neo4j Bolt connection URI",
    )
    neo4j_user: str = Field(
        default="neo4j",
        description="Neo4j username",
    )
    neo4j_password: str = Field(
        default="meshpassword",
        description="Neo4j password",
    )
    neo4j_max_connection_pool_size: int = Field(
        default=50,
        ge=5,
        description="Neo4j connection pool size",
    )

    # ─────────────────────────────────────────────────────────────
    # Security Firewall
    # ─────────────────────────────────────────────────────────────
    injection_detection_threshold: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Cosine similarity threshold for injection detection",
    )
    semantic_detection_enabled: bool = Field(
        default=True,
        description="Enable embedding-based semantic similarity checks",
    )
    embedding_model: str = Field(
        default="all-MiniLM-L6-v2",
        description="Sentence transformer model name",
    )
    max_prompt_analysis_length: int = Field(
        default=4096,
        ge=256,
        description="Max prompt chars to analyze",
    )

    # ─────────────────────────────────────────────────────────────
    # Docker Sandbox
    # ─────────────────────────────────────────────────────────────
    docker_socket: str = Field(
        default="/var/run/docker.sock",
        description="Docker socket path",
    )
    agent_sandbox_image: str = Field(
        default="python:3.11-slim",
        description="Base image for sandboxed agent containers",
    )
    sandbox_cpu_limit: float = Field(
        default=0.5,
        gt=0.0,
        description="Container CPU limit (fractional cores)",
    )
    sandbox_memory_limit: str = Field(
        default="512m",
        description="Container memory limit (e.g. 512m, 1g)",
    )
    sandbox_timeout: int = Field(
        default=30,
        ge=5,
        description="Container execution timeout (seconds)",
    )
    sandbox_network_mode: str = Field(
        default="none",
        description="Container network mode: none | bridge | host",
    )

    # ─────────────────────────────────────────────────────────────
    # Trust Graph Parameters
    # ─────────────────────────────────────────────────────────────
    initial_trust_score: int = Field(
        default=80,
        ge=0,
        le=100,
        description="Initial trust score for new agents",
    )
    trust_decay_rate: float = Field(
        default=2.0,
        ge=0.0,
        description="Trust score decay per hour (points)",
    )
    trust_quarantine_threshold: int = Field(
        default=20,
        ge=0,
        le=100,
        description="Trust score below which agent is quarantined",
    )
    trust_anomaly_penalty: int = Field(
        default=25,
        ge=0,
        le=100,
        description="Trust score penalty on anomaly detection",
    )

    # ─────────────────────────────────────────────────────────────
    # Attack Simulation
    # ─────────────────────────────────────────────────────────────
    attack_interval_seconds: int = Field(
        default=30,
        ge=5,
        description="Seconds between simulated attacks",
    )
    attack_simulation_enabled: bool = Field(
        default=False,
        description="Auto-run attack simulation on startup",
    )

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Enforce minimum secret key length."""
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        return v

    @property
    def is_production(self) -> bool:
        """Return True if running in production environment."""
        return self.env.lower() == "production"

    @property
    def has_azure_openai(self) -> bool:
        """Return True if Azure OpenAI credentials are configured."""
        return bool(self.azure_openai_endpoint and self.azure_openai_key)

    @property
    def has_github_models(self) -> bool:
        """Return True if GitHub Models token is configured."""
        return bool(self.github_token)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return cached Settings singleton.

    Using lru_cache ensures env vars are only parsed once,
    and the same object is reused across dependency injections.
    """
    return Settings()
