#!/usr/bin/env python3
"""
test_live_api.py - Test the real-time vulnerability APIs

Run this on YOUR machine (with internet) to see live results:
    python test_live_api.py

This demonstrates:
1. Querying OSV (Google's Open Source Vulnerability database)
2. Querying NVD (NIST National Vulnerability Database)
"""

from techscan.vulns_api import RealTimeVulnChecker, OSVClient, NVDClient


def test_osv():
    """Test OSV API directly"""
    print("\n" + "="*60)
    print("  TESTING OSV (Open Source Vulnerabilities) API")
    print("="*60 + "\n")
    
    osv = OSVClient()
    
    # Test 1: Query jQuery
    print("📦 Querying jQuery vulnerabilities...")
    vulns = osv.query_package('jquery', version='3.4.0', ecosystem='npm')
    
    print(f"\nFound {len(vulns)} vulnerabilities for jQuery 3.4.0:\n")
    for v in vulns[:5]:
        print(f"  🔴 {v['cve_id']}")
        print(f"     Severity: {v['severity'].upper()}")
        print(f"     {v['description'][:100]}...")
        print()


def test_nvd():
    """Test NVD API directly"""
    print("\n" + "="*60)
    print("  TESTING NVD (National Vulnerability Database) API")
    print("="*60 + "\n")
    
    nvd = NVDClient()
    
    # Test: Search for WordPress vulnerabilities
    print("📦 Searching NVD for 'wordpress' vulnerabilities...")
    print("   (This may take a moment due to rate limiting)\n")
    
    vulns = nvd.search_by_keyword('wordpress', max_results=5)
    
    print(f"Found {len(vulns)} vulnerabilities:\n")
    for v in vulns:
        print(f"  🔴 {v['cve_id']} (CVSS: {v['cvss_score']})")
        print(f"     {v['description'][:100]}...")
        print()


def test_combined():
    """Test the combined checker"""
    print("\n" + "="*60)
    print("  TESTING COMBINED REAL-TIME CHECKER")
    print("="*60 + "\n")
    
    # Use OSV only for speed (NVD has rate limits)
    checker = RealTimeVulnChecker(use_nvd=False, use_osv=True)
    
    # Simulate detected technologies
    detected_techs = [
        {
            'id': 'jquery',
            'name': 'jQuery',
            'version': '3.4.0',
            'category': 'JavaScript Library'
        },
        {
            'id': 'lodash',
            'name': 'Lodash',
            'version': '4.17.15',
            'category': 'JavaScript Library'
        }
    ]
    
    print("Checking detected technologies...\n")
    results = checker.check_all(detected_techs)
    
    print("\n" + "-"*60)
    print("RESULTS:")
    print("-"*60 + "\n")
    
    for tech in results:
        print(f"📦 {tech['name']} v{tech['version']}")
        print(f"   Vulnerabilities found: {tech['vuln_count']}")
        if tech['highest_severity']:
            print(f"   Highest severity: {tech['highest_severity'].upper()}")
        print()


if __name__ == "__main__":
    import sys
    
    print("""
╔════════════════════════════════════════════════════════════╗
║         REAL-TIME VULNERABILITY API TESTER                 ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    # Check for network
    try:
        import requests
        requests.get('https://api.osv.dev', timeout=5)
    except:
        print("❌ No network connection!")
        print("   This script requires internet access to query APIs.")
        print("   Please run this on a machine with internet access.")
        sys.exit(1)
    
    print("✅ Network connection confirmed!\n")
    
    # Run tests
    test_osv()
    # test_nvd()  # Uncomment to test NVD (slower due to rate limits)
    test_combined()
    
    print("\n✅ All tests complete!")
