from dataclasses import dataclass
from datetime import datetime


@dataclass
class Alert:
    id: str
    attack_type: str
    severity: str
    source_ip: str
    target_ip: str
    description: str
    timestamp: str = datetime.now().isoformat()

    def to_dict(self):
        return {
            "id": self.id,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "description": self.description,
            "timestamp": self.timestamp
        }