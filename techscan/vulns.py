"""
vulns.py - Vulnerability Lookup Module

This module checks detected technologies against known vulnerabilities (CVEs).

LEARNING NOTES:
- CVE = Common Vulnerabilities and Exposures (unique ID for each vulnerability)
- CVSS = Common Vulnerability Scoring System (0-10 severity score)
- NVD = National Vulnerability Database (maintained by NIST)

Version comparison is tricky! "3.5.0" vs "3.10.0" - which is newer?
We can't use simple string comparison because "10" > "5" but "10" < "5" as strings.
We need to compare each number part separately.
"""

import json
from pathlib import Path


def parse_version(version_string):
    """
    Parse a version string into comparable parts.
    
    Examples:
        "3.5.0" -> (3, 5, 0)
        "1.18.0" -> (1, 18, 0)
        "2.4.52" -> (2, 4, 52)
    
    LEARNING NOTE:
    This is important because string comparison fails:
    - "3.5.0" < "3.10.0" is FALSE as strings (because "5" > "1")
    - But 3.5.0 IS less than 3.10.0 numerically
    
    Args:
        version_string: Version like "3.5.0" or "1.18"
        
    Returns:
        tuple: Tuple of integers for comparison
    """
    if not version_string:
        return None
    
    try:
        # Split by dots and convert each part to integer
        # "3.5.0" -> ["3", "5", "0"] -> (3, 5, 0)
        parts = version_string.split('.')
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        # If conversion fails, return None
        return None


def version_in_range(version, min_version, max_version):
    """
    Check if a version falls within a vulnerable range.
    
    Args:
        version: The version to check (e.g., "3.4.0")
        min_version: Minimum affected version (e.g., "1.0.0")
        max_version: Maximum affected version (e.g., "3.5.0")
        
    Returns:
        bool: True if version is in the vulnerable range
        
    Example:
        version_in_range("3.4.0", "1.0.0", "3.5.0") -> True
        version_in_range("3.6.0", "1.0.0", "3.5.0") -> False
    """
    v = parse_version(version)
    min_v = parse_version(min_version)
    max_v = parse_version(max_version)
    
    if not all([v, min_v, max_v]):
        return False
    
    # Check: min_version <= version <= max_version
    return min_v <= v <= max_v


class VulnerabilityChecker:
    """
    Checks detected technologies for known vulnerabilities.
    
    How it works:
    1. Load vulnerability database (local JSON or API)
    2. For each detected technology with a version
    3. Check if that version falls in any vulnerable range
    4. Collect and return all matching CVEs
    """
    
    def __init__(self, vuln_db_path=None):
        """
        Initialize the vulnerability checker.
        
        Args:
            vuln_db_path: Path to vulnerability database JSON
        """
        if vuln_db_path is None:
            base_dir = Path(__file__).parent.parent
            vuln_db_path = base_dir / "data" / "vulnerabilities.json"
        
        self.vuln_db = self._load_database(vuln_db_path)
    
    def _load_database(self, path):
        """Load the vulnerability database from JSON."""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                return data.get('vulnerabilities', {})
        except FileNotFoundError:
            print(f"⚠️  Vulnerability database not found: {path}")
            return {}
        except json.JSONDecodeError:
            print(f"⚠️  Invalid JSON in vulnerability database")
            return {}
    
    def check_technology(self, tech_id, version):
        """
        Check a single technology for vulnerabilities.
        
        Args:
            tech_id: Technology identifier (e.g., "jquery", "wordpress")
            version: Version string (e.g., "3.4.0")
            
        Returns:
            list: List of matching vulnerabilities
        """
        if not version:
            return []
        
        # Normalize tech_id (lowercase, no special chars)
        tech_id = tech_id.lower().replace('.', '').replace('-', '_')
        
        # Get vulnerabilities for this technology
        tech_vulns = self.vuln_db.get(tech_id, [])
        
        matching_vulns = []
        
        for vuln in tech_vulns:
            affected = vuln.get('affected_versions', {})
            min_v = affected.get('min', '0.0.0')
            max_v = affected.get('max', '999.999.999')
            
            if version_in_range(version, min_v, max_v):
                matching_vulns.append({
                    'cve_id': vuln.get('cve_id'),
                    'severity': vuln.get('severity', 'unknown'),
                    'cvss_score': vuln.get('cvss_score', 0),
                    'description': vuln.get('description', ''),
                    'fixed_version': vuln.get('fixed_version'),
                    'published': vuln.get('published')
                })
        
        return matching_vulns
    
    def check_all(self, technologies):
        """
        Check all detected technologies for vulnerabilities.
        
        Args:
            technologies: List of detected tech dicts from detector
            
        Returns:
            list: Technologies with their vulnerabilities added
        """
        results = []
        
        for tech in technologies:
            tech_id = tech.get('id', '')
            version = tech.get('version')
            
            vulns = self.check_technology(tech_id, version)
            
            # Add vulnerability info to the tech dict
            tech_with_vulns = tech.copy()
            tech_with_vulns['vulnerabilities'] = vulns
            tech_with_vulns['vuln_count'] = len(vulns)
            
            # Determine highest severity
            if vulns:
                severities = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
                max_severity = max(vulns, key=lambda v: severities.get(v['severity'], 0))
                tech_with_vulns['highest_severity'] = max_severity['severity']
            else:
                tech_with_vulns['highest_severity'] = None
            
            results.append(tech_with_vulns)
        
        return results
    
    def get_summary(self, checked_technologies):
        """
        Generate a summary of vulnerability findings.
        
        Args:
            checked_technologies: Output from check_all()
            
        Returns:
            dict: Summary statistics
        """
        total_vulns = sum(t['vuln_count'] for t in checked_technologies)
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for tech in checked_technologies:
            for vuln in tech.get('vulnerabilities', []):
                sev = vuln.get('severity', 'unknown')
                if sev in severity_counts:
                    severity_counts[sev] += 1
        
        # Count techs with/without vulns
        with_vulns = sum(1 for t in checked_technologies if t['vuln_count'] > 0)
        without_vulns = len(checked_technologies) - with_vulns
        
        return {
            'total_technologies': len(checked_technologies),
            'technologies_with_vulns': with_vulns,
            'technologies_safe': without_vulns,
            'total_vulnerabilities': total_vulns,
            'by_severity': severity_counts
        }


# Test the module directly
if __name__ == "__main__":
    checker = VulnerabilityChecker()
    
    # Test with some sample technologies
    sample_techs = [
        {'id': 'jquery', 'name': 'jQuery', 'version': '3.4.0', 'category': 'JavaScript Library'},
        {'id': 'wordpress', 'name': 'WordPress', 'version': '6.2.0', 'category': 'CMS'},
        {'id': 'nginx', 'name': 'Nginx', 'version': '1.18.0', 'category': 'Web Server'},
    ]
    
    print("🔍 Checking for vulnerabilities...\n")
    
    results = checker.check_all(sample_techs)
    
    for tech in results:
        print(f"📦 {tech['name']} v{tech['version']}")
        if tech['vulnerabilities']:
            print(f"   ⚠️  Found {tech['vuln_count']} vulnerabilities:")
            for vuln in tech['vulnerabilities']:
                sev_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(vuln['severity'], '⚪')
                print(f"      {sev_emoji} {vuln['cve_id']} ({vuln['severity'].upper()}, CVSS: {vuln['cvss_score']})")
        else:
            print(f"   ✅ No known vulnerabilities")
        print()
    
    # Print summary
    summary = checker.get_summary(results)
    print("=" * 50)
    print(f"Summary: {summary['total_vulnerabilities']} vulnerabilities found")
    print(f"  Critical: {summary['by_severity']['critical']}")
    print(f"  High: {summary['by_severity']['high']}")
    print(f"  Medium: {summary['by_severity']['medium']}")
    print(f"  Low: {summary['by_severity']['low']}")