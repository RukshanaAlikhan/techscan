"""
vulns_api.py - Real-Time Vulnerability Lookup

This module queries LIVE vulnerability databases:
1. NVD (National Vulnerability Database) - nvd.nist.gov
2. OSV (Open Source Vulnerabilities) - osv.dev

LEARNING NOTES:
- APIs return JSON data we can parse
- We search by "CPE" (Common Platform Enumeration) for NVD
- CPE is a naming scheme: cpe:2.3:a:vendor:product:version
- OSV uses simpler package name + version queries

API ENDPOINTS:
- NVD: https://services.nvd.nist.gov/rest/json/cves/2.0
- OSV: https://api.osv.dev/v1/query

NO API KEY NEEDED for basic queries (NVD has rate limits though)
"""

import requests
import time
from typing import List, Dict, Optional


class NVDClient:
    """
    Client for the National Vulnerability Database (NVD) API.
    
    NVD is maintained by NIST and is the most comprehensive 
    vulnerability database for the US government.
    
    API Docs: https://nvd.nist.gov/developers/vulnerabilities
    
    RATE LIMITS (without API key):
    - 5 requests per 30 seconds
    - With API key: 50 requests per 30 seconds
    
    Get free API key at: https://nvd.nist.gov/developers/request-an-api-key
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD client.
        
        Args:
            api_key: Optional NVD API key for higher rate limits
        """
        self.api_key = api_key
        self.headers = {}
        if api_key:
            self.headers['apiKey'] = api_key
        
        # Track requests for rate limiting
        self.last_request_time = 0
        self.min_request_interval = 6  # seconds between requests (5 per 30s)
    
    def _rate_limit(self):
        """Ensure we don't exceed rate limits."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            sleep_time = self.min_request_interval - elapsed
            print(f"   ⏳ Rate limiting: waiting {sleep_time:.1f}s...")
            time.sleep(sleep_time)
        self.last_request_time = time.time()
    
    def search_by_keyword(self, keyword: str, max_results: int = 10) -> List[Dict]:
        """
        Search NVD for vulnerabilities by keyword.
        
        Args:
            keyword: Technology name (e.g., "jquery", "wordpress")
            max_results: Maximum number of results to return
            
        Returns:
            List of vulnerability dictionaries
        """
        self._rate_limit()
        
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': max_results
        }
        
        try:
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            return self._parse_nvd_response(data)
            
        except requests.exceptions.RequestException as e:
            print(f"   ⚠️ NVD API error: {e}")
            return []
    
    def search_by_cpe(self, vendor: str, product: str, version: str = None) -> List[Dict]:
        """
        Search NVD using CPE (Common Platform Enumeration).
        
        CPE format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        
        Args:
            vendor: Vendor name (e.g., "jquery", "automattic")
            product: Product name (e.g., "jquery", "wordpress")
            version: Specific version (optional)
            
        Returns:
            List of vulnerability dictionaries
        """
        self._rate_limit()
        
        # Build CPE string
        # 'a' = application, could also be 'o' for OS, 'h' for hardware
        if version:
            cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        else:
            cpe = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"
        
        params = {
            'cpeName': cpe,
            'resultsPerPage': 50
        }
        
        try:
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            return self._parse_nvd_response(data)
            
        except requests.exceptions.RequestException as e:
            print(f"   ⚠️ NVD API error: {e}")
            return []
    
    def _parse_nvd_response(self, data: Dict) -> List[Dict]:
        """Parse NVD API response into our standard format."""
        vulnerabilities = []
        
        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            
            # Get CVE ID
            cve_id = cve.get('id', 'Unknown')
            
            # Get description (English)
            descriptions = cve.get('descriptions', [])
            description = next(
                (d['value'] for d in descriptions if d.get('lang') == 'en'),
                'No description available'
            )
            
            # Get CVSS score and severity
            metrics = cve.get('metrics', {})
            cvss_score = 0
            severity = 'unknown'
            
            # Try CVSS 3.1 first, then 3.0, then 2.0
            for cvss_version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if cvss_version in metrics and metrics[cvss_version]:
                    cvss_data = metrics[cvss_version][0]
                    if 'cvssData' in cvss_data:
                        cvss_score = cvss_data['cvssData'].get('baseScore', 0)
                        severity = cvss_data['cvssData'].get('baseSeverity', 'unknown').lower()
                    break
            
            # Get published date
            published = cve.get('published', '')[:10]  # Just the date part
            
            # Get affected versions from configurations
            affected_versions = self._extract_affected_versions(cve)
            
            vulnerabilities.append({
                'cve_id': cve_id,
                'description': description[:500],  # Truncate long descriptions
                'cvss_score': cvss_score,
                'severity': severity,
                'published': published,
                'affected_versions': affected_versions,
                'source': 'NVD'
            })
        
        return vulnerabilities
    
    def _extract_affected_versions(self, cve: Dict) -> Dict:
        """Extract affected version range from CVE configurations."""
        # This is complex in NVD - simplified version
        configs = cve.get('configurations', [])
        
        versions = {'min': None, 'max': None}
        
        for config in configs:
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if match.get('vulnerable', False):
                        if 'versionStartIncluding' in match:
                            versions['min'] = match['versionStartIncluding']
                        if 'versionEndExcluding' in match:
                            versions['max'] = match['versionEndExcluding']
                        elif 'versionEndIncluding' in match:
                            versions['max'] = match['versionEndIncluding']
        
        return versions


class OSVClient:
    """
    Client for the OSV (Open Source Vulnerabilities) API.
    
    OSV is Google's aggregated vulnerability database focused on
    open source software. It's simpler to use than NVD.
    
    API Docs: https://osv.dev/docs/
    
    NO RATE LIMITS for reasonable usage!
    """
    
    BASE_URL = "https://api.osv.dev/v1"
    
    # Map our tech names to OSV ecosystem/package names
    ECOSYSTEM_MAP = {
        'jquery': ('npm', 'jquery'),
        'bootstrap': ('npm', 'bootstrap'),
        'vue': ('npm', 'vue'),
        'react': ('npm', 'react'),
        'angular': ('npm', '@angular/core'),
        'express': ('npm', 'express'),
        'lodash': ('npm', 'lodash'),
        'wordpress': ('WordPress', 'wordpress'),
        'django': ('PyPI', 'django'),
        'flask': ('PyPI', 'flask'),
        'laravel': ('Packagist', 'laravel/framework'),
        'rails': ('RubyGems', 'rails'),
    }
    
    def query_package(self, package_name: str, version: str = None, ecosystem: str = None) -> List[Dict]:
        """
        Query OSV for vulnerabilities in a specific package.
        
        Args:
            package_name: Name of the package
            version: Specific version to check
            ecosystem: Package ecosystem (npm, PyPI, etc.)
            
        Returns:
            List of vulnerability dictionaries
        """
        # Try to map to known ecosystem
        if package_name.lower() in self.ECOSYSTEM_MAP:
            ecosystem, package_name = self.ECOSYSTEM_MAP[package_name.lower()]
        
        # Build query
        query = {
            'package': {
                'name': package_name
            }
        }
        
        if ecosystem:
            query['package']['ecosystem'] = ecosystem
        
        if version:
            query['version'] = version
        
        try:
            response = requests.post(
                f"{self.BASE_URL}/query",
                json=query,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            return self._parse_osv_response(data)
            
        except requests.exceptions.RequestException as e:
            print(f"   ⚠️ OSV API error: {e}")
            return []
    
    def _parse_osv_response(self, data: Dict) -> List[Dict]:
        """Parse OSV API response into our standard format."""
        vulnerabilities = []
        
        for vuln in data.get('vulns', []):
            # Get the CVE ID if available, otherwise use OSV ID
            aliases = vuln.get('aliases', [])
            cve_id = next(
                (a for a in aliases if a.startswith('CVE-')),
                vuln.get('id', 'Unknown')
            )
            
            # Get severity from database_specific or severity field
            severity = 'unknown'
            cvss_score = 0
            
            if 'severity' in vuln:
                for sev in vuln['severity']:
                    if sev.get('type') == 'CVSS_V3':
                        # Parse CVSS score from vector string
                        score_str = sev.get('score', '')
                        try:
                            # CVSS vector often contains score
                            if '/' in score_str:
                                cvss_score = float(score_str.split('/')[0])
                        except:
                            pass
            
            # Determine severity from score
            if cvss_score >= 9.0:
                severity = 'critical'
            elif cvss_score >= 7.0:
                severity = 'high'
            elif cvss_score >= 4.0:
                severity = 'medium'
            elif cvss_score > 0:
                severity = 'low'
            
            # Get description
            description = vuln.get('summary', vuln.get('details', 'No description'))[:500]
            
            # Get published date
            published = vuln.get('published', '')[:10]
            
            # Get affected versions
            affected_versions = {'min': None, 'max': None}
            for affected in vuln.get('affected', []):
                for range_info in affected.get('ranges', []):
                    for event in range_info.get('events', []):
                        if 'introduced' in event:
                            affected_versions['min'] = event['introduced']
                        if 'fixed' in event:
                            affected_versions['fixed'] = event['fixed']
            
            vulnerabilities.append({
                'cve_id': cve_id,
                'osv_id': vuln.get('id'),
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity,
                'published': published,
                'affected_versions': affected_versions,
                'source': 'OSV'
            })
        
        return vulnerabilities


class RealTimeVulnChecker:
    """
    Combined vulnerability checker using multiple data sources.
    
    This class tries multiple APIs to get the best coverage:
    1. OSV (fast, good for npm/PyPI packages)
    2. NVD (comprehensive, but slower due to rate limits)
    """
    
    def __init__(self, nvd_api_key: str = None, use_nvd: bool = True, use_osv: bool = True):
        """
        Initialize the real-time vulnerability checker.
        
        Args:
            nvd_api_key: Optional NVD API key for higher rate limits
            use_nvd: Whether to query NVD
            use_osv: Whether to query OSV
        """
        self.use_nvd = use_nvd
        self.use_osv = use_osv
        
        if use_nvd:
            self.nvd = NVDClient(api_key=nvd_api_key)
        if use_osv:
            self.osv = OSVClient()
    
    def check_technology(self, tech_name: str, version: str = None) -> List[Dict]:
        """
        Check a technology for vulnerabilities using all available sources.
        
        Args:
            tech_name: Technology name (e.g., "jquery", "wordpress")
            version: Version string (optional but recommended)
            
        Returns:
            List of vulnerability dictionaries
        """
        all_vulns = []
        seen_cves = set()  # Avoid duplicates
        
        print(f"   🔍 Checking {tech_name}" + (f" v{version}" if version else ""))
        
        # Try OSV first (faster, no rate limits)
        if self.use_osv:
            print(f"      → Querying OSV...")
            osv_vulns = self.osv.query_package(tech_name, version)
            for vuln in osv_vulns:
                if vuln['cve_id'] not in seen_cves:
                    seen_cves.add(vuln['cve_id'])
                    all_vulns.append(vuln)
            print(f"      → OSV: Found {len(osv_vulns)} vulnerabilities")
        
        # Then try NVD (more comprehensive but slower)
        if self.use_nvd:
            print(f"      → Querying NVD...")
            nvd_vulns = self.nvd.search_by_keyword(tech_name)
            for vuln in nvd_vulns:
                if vuln['cve_id'] not in seen_cves:
                    seen_cves.add(vuln['cve_id'])
                    all_vulns.append(vuln)
            print(f"      → NVD: Found {len(nvd_vulns)} vulnerabilities")
        
        return all_vulns
    
    def check_all(self, technologies: List[Dict]) -> List[Dict]:
        """
        Check all detected technologies for vulnerabilities.
        
        Args:
            technologies: List of tech dicts from detector
            
        Returns:
            Technologies with vulnerability info added
        """
        results = []
        
        for tech in technologies:
            tech_name = tech.get('name', tech.get('id', ''))
            version = tech.get('version')
            
            vulns = self.check_technology(tech_name, version)
            
            # Filter vulnerabilities to only those affecting this version
            if version:
                vulns = self._filter_by_version(vulns, version)
            
            tech_with_vulns = tech.copy()
            tech_with_vulns['vulnerabilities'] = vulns
            tech_with_vulns['vuln_count'] = len(vulns)
            
            # Determine highest severity
            if vulns:
                severities = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
                max_sev = max(vulns, key=lambda v: severities.get(v.get('severity', 'unknown'), 0))
                tech_with_vulns['highest_severity'] = max_sev.get('severity')
            else:
                tech_with_vulns['highest_severity'] = None
            
            results.append(tech_with_vulns)
        
        return results
    
    def _filter_by_version(self, vulns: List[Dict], version: str) -> List[Dict]:
        """
        Filter vulnerabilities to only those affecting the specific version.
        
        Note: This is a simplified filter. Real version comparison is complex.
        """
        # For now, return all vulns - proper filtering requires version parsing
        # TODO: Implement proper semver comparison
        return vulns


# Test the module directly
if __name__ == "__main__":
    print("\n🔐 Real-Time Vulnerability Checker Test\n")
    print("=" * 50)
    
    # Test with OSV only (faster, no rate limits)
    checker = RealTimeVulnChecker(use_nvd=False, use_osv=True)
    
    # Test packages
    test_packages = [
        ('jquery', '3.4.0'),
        ('lodash', '4.17.15'),
        ('express', '4.17.0'),
    ]
    
    for name, version in test_packages:
        print(f"\n📦 Testing {name} v{version}")
        vulns = checker.check_technology(name, version)
        
        if vulns:
            print(f"\n   Found {len(vulns)} vulnerabilities:")
            for v in vulns[:5]:  # Show first 5
                print(f"   • {v['cve_id']} ({v['severity'].upper()})")
                print(f"     {v['description'][:100]}...")
        else:
            print("   ✅ No vulnerabilities found")
        print()
