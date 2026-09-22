from dataclasses import dataclass


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str = "Unknown"
    vendor: str = "Unknown"
    status: str = "Active"

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "status": self.status
        }