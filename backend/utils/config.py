import os
import json
import configparser
from typing import Dict, Any, Optional
from pathlib import Path

class Config:
    """Configuration management for SHADOWPULSE"""
    
    def __init__(self, config_file: str = 'shadowpulse.conf'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self._load_config()
        self._load_env_overrides()
    
    def _load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration file"""
        self.config['SYSTEM'] = {
            'debug': 'False',
            'log_level': 'INFO',
            'data_retention_days': '30',
            'max_log_size': '100MB',
            'backup_enabled': 'True'
        }
        
        self.config['NETWORK'] = {
            'interface': 'auto',
            'monitor_mode': 'False',
            'capture_buffer_size': '65536',
            'scan_interval': '300',
            'network_range': 'auto',
            'timeout': '5'
        }
        
        self.config['DETECTORS'] = {
            'arp_spoof_enabled': 'True',
            'dhcp_spoofing_enabled': 'True',
            'dns_spoof_enabled': 'True',
            'http_injection_enabled': 'True',
            'icmp_redirect_enabled': 'True',
            'rogue_access_enabled': 'True',
            'ssl_strip_enabled': 'True'
        }
        
        self.config['ALERTS'] = {
            'severity_threshold': 'medium',
            'email_notifications': 'True',
            'sms_notifications': 'False',
            'webhook_url': '',
            'alert_cooldown': '60'
        }
        
        self.config['DATABASE'] = {
            'type': 'sqlite',
            'path': 'shadowpulse.db',
            'pool_size': '10',
            'timeout': '30'
        }
        
        self.config['API'] = {
            'host': '0.0.0.0',
            'port': '5000',
            'secret_key': 'change_this_secret_key',
            'cors_enabled': 'True',
            'rate_limit': '1000'
        }
        
        self.save_config()
    
    def _load_env_overrides(self):
        """Load environment variable overrides"""
        env_mappings = {
            'SHADOWPULSE_DEBUG': ('SYSTEM', 'debug'),
            'SHADOWPULSE_INTERFACE': ('NETWORK', 'interface'),
            'SHADOWPULSE_DB_PATH': ('DATABASE', 'path'),
            'SHADOWPULSE_API_PORT': ('API', 'port'),
            'SHADOWPULSE_SECRET_KEY': ('API', 'secret_key')
        }
        
        for env_var, (section, key) in env_mappings.items():
            if env_var in os.environ:
                self.config.set(section, key, os.environ[env_var])
    
    def get(self, section: str, key: str, fallback: Any = None) -> Any:
        """Get configuration value"""
        try:
            value = self.config.get(section, key)
            # Type conversion
            if value.lower() in ('true', 'false'):
                return value.lower() == 'true'
            if value.isdigit():
                return int(value)
            return value
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback
    
    def set(self, section: str, key: str, value: Any):
        """Set configuration value"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, key, str(value))
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            self.config.write(f)
    
    def get_detector_config(self) -> Dict[str, bool]:
        """Get detector configuration"""
        return {
            'arp_spoof': self.get('DETECTORS', 'arp_spoof_enabled', True),
            'dhcp_spoofing': self.get('DETECTORS', 'dhcp_spoofing_enabled', True),
            'dns_spoof': self.get('DETECTORS', 'dns_spoof_enabled', True),
            'http_injection': self.get('DETECTORS', 'http_injection_enabled', True),
            'icmp_redirect': self.get('DETECTORS', 'icmp_redirect_enabled', True),
            'rogue_access': self.get('DETECTORS', 'rogue_access_enabled', True),
            'ssl_strip': self.get('DETECTORS', 'ssl_strip_enabled', True)
        }
    
    def get_network_config(self) -> Dict[str, Any]:
        """Get network configuration."""
        iface = self.get('NETWORK', 'interface', 'auto')
        network_range = self.get('NETWORK', 'network_range', 'auto')
        return {
            'interface': iface,
            'monitor_mode': self.get('NETWORK', 'monitor_mode'),
            'capture_buffer_size': self.get('NETWORK', 'capture_buffer_size'),
            'scan_interval': self.get('NETWORK', 'scan_interval'),
            'network_range': network_range,
            'timeout': self.get('NETWORK', 'timeout')
        }

# Global config instance
_config_instance = None

def get_config() -> Config:
    """Get global configuration instance"""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance
