import json
import os
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

# Try importing pyyaml, fallback to json if unavailable
try:
    import yaml
    HAS_YAML = True
except ImportError:
    yaml = None
    HAS_YAML = False


class ScopeConfig(BaseModel):
    allowed_cidrs: List[str] = Field(default_factory=lambda: ["127.0.0.1/32", "192.168.1.0/24"])
    allowed_ports: Optional[List[int]] = None
    max_scan_timeout_seconds: int = 1200  # 20 minutes for Great tier


class AgentConfig(BaseModel):
    name: str
    enabled: bool = True
    role: str
    surface: str  # network, web, binary
    triggers: List[str] = Field(default_factory=list)
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ReportingConfig(BaseModel):
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    export_dir: str = "./reports"
    auto_generate_on_finish: bool = True


class EngineConfig(BaseModel):
    project_name: str = "CyberForge Autonomous PTES Engine"
    tier: str = "recon"
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    agents: List[AgentConfig] = Field(default_factory=list)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)


def load_config(config_path: str = "config.json") -> EngineConfig:
    """
    Loads engine and agent configuration dynamically from JSON or YAML (Bonus B-4).
    Supports config.json natively and config.yaml when pyyaml is installed.
    """
    if not os.path.exists(config_path):
        if os.path.exists("config.json"):
            config_path = "config.json"
        elif os.path.exists("config.yaml"):
            config_path = "config.yaml"
        else:
            return EngineConfig()

    with open(config_path, "r", encoding="utf-8") as f:
        if config_path.endswith(".json"):
            data = json.load(f)
        elif config_path.endswith((".yaml", ".yml")):
            if HAS_YAML and yaml:
                data = yaml.safe_load(f) or {}
            else:
                data = {}
        else:
            data = {}

    return EngineConfig.model_validate(data)
