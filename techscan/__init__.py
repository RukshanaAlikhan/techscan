"""
TechScan - Security-focused Technology Stack Analyzer
"""

from .detector import TechDetector
from .vulns import VulnerabilityChecker

try:
    from .vulns_api import RealTimeVulnChecker, NVDClient, OSVClient
    ONLINE_AVAILABLE = True
except ImportError:
    ONLINE_AVAILABLE = False

__version__ = "0.1.0"
__all__ = ['TechDetector', 'VulnerabilityChecker']