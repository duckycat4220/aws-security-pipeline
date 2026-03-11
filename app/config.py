from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "AWS Security Intelligence Pipeline"
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    log_level: str = "INFO"

    aws_region: str = "us-east-1"
    aws_access_key_id: str = "test"
    aws_secret_access_key: str = "test"
    aws_endpoint_url: str = "http://localhost:4566"

    sqs_queue_name: str = "security-events-queue"
    sqs_dlq_name: str = "security-events-dlq"
    sqs_max_receive_count: int = 3

    callback_url: str = "http://webhook.site/replace-me"
    callback_timeout_seconds: int = 10

    # LLM: "mock" for rule-based responses, "bedrock" for Claude via AWS Bedrock
    llm_mode: str = "mock"
    bedrock_model_id: str = "anthropic.claude-haiku-4-5-20251001"
    bedrock_region: str = "us-east-1"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )
    
settings = Settings()