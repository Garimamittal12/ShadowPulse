import logging
import logging.handlers
import os
import sys
from datetime import datetime
from typing import Optional
from pathlib import Path

class Logger:
    """Enhanced logging system for SHADOWPULSE"""
    
    def __init__(self, name: str = 'shadowpulse', log_dir: str = 'logs'):
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        """Setup logging handlers"""
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)
        
        # Main log file handler with rotation
        main_log = self.log_dir / 'shadowpulse.log'
        file_handler = logging.handlers.RotatingFileHandler(
            main_log, maxBytes=50*1024*1024, backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)
        
        # Security events log
        security_log = self.log_dir / 'security.log'
        security_handler = logging.handlers.TimedRotatingFileHandler(
            security_log, when='midnight', interval=1, backupCount=30
        )
        security_handler.setLevel(logging.WARNING)
        security_handler.setFormatter(file_format)
        self.logger.addHandler(security_handler)
        
        # Network traffic log
        network_log = self.log_dir / 'network.log'
        network_handler = logging.handlers.RotatingFileHandler(
            network_log, maxBytes=100*1024*1024, backupCount=3
        )
        network_handler.setLevel(logging.INFO)
        network_handler.setFormatter(file_format)
        # Create separate logger for network events
        network_logger = logging.getLogger(f'{self.name}.network')
        network_logger.addHandler(network_handler)
        network_logger.setLevel(logging.INFO)
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(message, extra=kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.logger.warning(message, extra=kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        self.logger.error(message, extra=kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self.logger.critical(message, extra=kwargs)
    
    def security_event(self, event_type: str, severity: str, details: dict):
        """Log security event"""
        message = f"SECURITY EVENT - Type: {event_type}, Severity: {severity}, Details: {details}"
        if severity.upper() in ['HIGH', 'CRITICAL']:
            self.logger.critical(message)
        else:
            self.logger.warning(message)
    
    def network_event(self, source_ip: str, dest_ip: str, protocol: str, details: str):
        """Log network event"""
        network_logger = logging.getLogger(f'{self.name}.network')
        message = f"NETWORK - {source_ip} -> {dest_ip} [{protocol}] {details}"
        network_logger.info(message)
    
    def detector_event(self, detector: str, action: str, details: dict):
        """Log detector event"""
        message = f"DETECTOR [{detector}] - {action}: {details}"
        self.logger.info(message)

def setup_logging(log_level: str = 'INFO', log_dir: str = 'logs') -> Logger:
    """Setup global logging configuration"""
    # Set root logger level
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.root.setLevel(numeric_level)
    
    # Create main logger instance
    logger = Logger('shadowpulse', log_dir)
    
    # Log startup
    logger.info("SHADOWPULSE logging system initialized")
    logger.info(f"Log level set to: {log_level}")
    logger.info(f"Log directory: {log_dir}")
    
    return logger

# Global logger instance
_logger_instance = None

def get_logger() -> Logger:
    """Get global logger instance"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = setup_logging()
    return _logger_instance