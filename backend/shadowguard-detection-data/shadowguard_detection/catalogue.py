from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class Application:
    name: str
    domain: str | None
    publisher: str | None
    category: str
    approval_state: str
    risk_weight: int


class ApplicationCatalogue:
    def __init__(self, applications: list[Application]):
        self.applications = applications

    @classmethod
    def from_json(cls, path: str | Path) -> "ApplicationCatalogue":
        return cls([Application(**item) for item in json.loads(Path(path).read_text())])

    def find(self, domain: str | None = None, publisher: str | None = None) -> Application | None:
        normal_domain = domain.lower().strip().rstrip(".") if domain else None
        normal_publisher = publisher.lower().strip() if publisher else None
        for app in self.applications:
            if normal_domain and app.domain and (normal_domain == app.domain or normal_domain.endswith("." + app.domain)):
                return app
            if normal_publisher and app.publisher and normal_publisher == app.publisher.lower():
                return app
        return None
