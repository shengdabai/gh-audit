import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from gh_audit.models import Finding


@dataclass
class ScanConfig:
    repo: str
    branch: str
    commit_sha: str
    is_public: bool
    history_depth: int = 100


class BaseScanner(ABC):
    name: str = "base"

    def is_available(self) -> bool:
        return True

    @abstractmethod
    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        ...

    def _external_tool_available(self, tool_name: str) -> bool:
        return shutil.which(tool_name) is not None
