from dataclasses import dataclass
from datetime import datetime


@dataclass
class Log:
    level: str
    message: str
    timestamp: str = datetime.now().isoformat()

    def to_dict(self):
        return {
            "level": self.level,
            "message": self.message,
            "timestamp": self.timestamp
        }