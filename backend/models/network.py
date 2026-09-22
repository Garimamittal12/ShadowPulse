from dataclasses import dataclass


@dataclass
class Network:
    interface: str
    gateway_ip: str
    gateway_mac: str
    subnet: str
    dns_server: str

    def to_dict(self):
        return {
            "interface": self.interface,
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "subnet": self.subnet,
            "dns_server": self.dns_server
        }