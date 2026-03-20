from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Entra ID
    tenant_id: str = ""
    redirect_uri: str = "http://localhost:8000/auth/callback"

    # Client app
    client_id: str = ""
    client_secret: str = ""

    # Resource API A
    api_a_app_id: str = ""
    api_a_client_secret: str = ""
    api_a_scope: str = ""
    api_a_base_url: str = "http://localhost:8001"

    # Resource API B
    api_b_app_id: str = ""
    api_b_scope: str = ""
    api_b_base_url: str = "http://localhost:8002"

    # Agent ID
    agent_blueprint_app_id: str = ""
    agent_blueprint_secret: str = ""
    agent_identity_id: str = ""
    agent_identity_tenant_id: str = ""

    # Session
    session_secret: str = "change-me"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"

    @property
    def token_endpoint(self) -> str:
        return f"{self.authority}/oauth2/v2.0/token"

    @property
    def authorize_endpoint(self) -> str:
        return f"{self.authority}/oauth2/v2.0/authorize"

    @property
    def device_code_endpoint(self) -> str:
        return f"{self.authority}/oauth2/v2.0/devicecode"

    @property
    def api_a_app_uri(self) -> str:
        return f"api://{self.api_a_app_id}" if self.api_a_app_id else ""

    @property
    def api_b_app_uri(self) -> str:
        return f"api://{self.api_b_app_id}" if self.api_b_app_id else ""

    @property
    def agent_blueprint_app_uri(self) -> str:
        return f"api://{self.agent_blueprint_app_id}" if self.agent_blueprint_app_id else ""

    @property
    def agent_blueprint_scope(self) -> str:
        return f"api://{self.agent_blueprint_app_id}/access_as_user" if self.agent_blueprint_app_id else ""

    @property
    def agent_token_endpoint(self) -> str:
        tenant = self.agent_identity_tenant_id or self.tenant_id
        return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

    def is_agent_id_configured(self) -> bool:
        return bool(
            self.agent_blueprint_app_id
            and self.agent_blueprint_secret
            and self.agent_identity_id
        )


settings = Settings()
