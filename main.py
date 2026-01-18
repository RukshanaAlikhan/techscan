#!/usr/bin/env python3
"""
main.py - TechScan CLI Entry Point

This is what you run from the command line:
    python main.py https://example.com
"""

import sys
import os

# === FIX FOR IMPORT ERRORS ===
# Add the current directory to Python's path so it can find 'techscan' module
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)
# =============================

import argparse
from techscan.detector import TechDetector
from techscan.vulns import VulnerabilityChecker
# Try to import real-time checker (requires network)
try:
    from techscan.vulns_api import RealTimeVulnChecker
    ONLINE_AVAILABLE = True
except ImportError:
    ONLINE_AVAILABLE = False


def print_banner():
    """Print a nice ASCII banner"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ████████╗███████╗ ██████╗██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗  ║
║   ╚══██╔══╝██╔════╝██╔════╝██║  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║  ║
║      ██║   █████╗  ██║     ███████║███████╗██║     ███████║██╔██╗ ██║  ║
║      ██║   ██╔══╝  ██║     ██╔══██║╚════██║██║     ██╔══██║██║╚██╗██║  ║
║      ██║   ███████╗╚██████╗██║  ██║███████║╚██████╗██║  ██║██║ ╚████║  ║
║      ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ║
║                                                           ║
║           Security-Focused Tech Stack Analyzer            ║
║                        v0.1.0                             ║
╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_results(result, vuln_results=None, summary=None):
    """
    Print scan results in a nice format.
    
    Args:
        result: Dictionary containing scan results
        vuln_results: Technologies with vulnerability info (optional)
        summary: Vulnerability summary (optional)
    """
    if result['status'] == 'error':
        print(f"\n❌ Error scanning {result['url']}")
        print(f"   {result['error']}")
        return
    
    techs = vuln_results if vuln_results else result['technologies']
    
    if not techs:
        print("\n🤷 No technologies detected.")
        print("   This could mean:")
        print("   • The site uses uncommon technologies")
        print("   • Technologies are well-hidden")
        print("   • Our signatures need updating")
        return
    
    print(f"\n{'='*60}")
    print(f"  SCAN RESULTS")
    print(f"{'='*60}\n")
    
    # Group by category
    categories = {}
    for tech in techs:
        cat = tech['category']
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(tech)
    
    # Severity emojis and colors
    sev_emoji = {
        'critical': '🔴',
        'high': '🟠', 
        'medium': '🟡',
        'low': '🟢',
        None: '✅'
    }
    
    # Print each category
    for category, items in sorted(categories.items()):
        print(f"  📁 {category}")
        for tech in items:
            version_str = f" v{tech['version']}" if tech.get('version') else " (version unknown)"
            
            # Check if we have vulnerability info
            vuln_count = tech.get('vuln_count', 0)
            highest_sev = tech.get('highest_severity')
            
            status_emoji = sev_emoji.get(highest_sev, '⚪')
            
            if vuln_count > 0:
                print(f"     └─ {status_emoji} {tech['name']}{version_str} - {vuln_count} vulnerability(ies)")
                # Show CVE details
                for vuln in tech.get('vulnerabilities', []):
                    v_emoji = sev_emoji.get(vuln['severity'], '⚪')
                    print(f"        {v_emoji} {vuln['cve_id']} ({vuln['severity'].upper()}, CVSS: {vuln['cvss_score']})")
                    if vuln.get('fixed_version'):
                        print(f"           → Fix: upgrade to v{vuln['fixed_version']}")
            else:
                if tech.get('version'):
                    print(f"     └─ ✅ {tech['name']}{version_str} - No known vulnerabilities")
                else:
                    print(f"     └─ ⚪ {tech['name']}{version_str} - Cannot check (no version)")
        print()
    
    # Print summary
    print(f"{'─'*60}")
    print(f"  SUMMARY")
    print(f"{'─'*60}")
    print(f"  Technologies detected: {len(techs)}")
    
    if summary:
        with_vulns = summary['technologies_with_vulns']
        total_vulns = summary['total_vulnerabilities']
        
        print(f"  Vulnerable components: {with_vulns}")
        print(f"  Total vulnerabilities: {total_vulns}")
        
        if total_vulns > 0:
            print(f"\n  Breakdown by severity:")
            print(f"    🔴 Critical: {summary['by_severity']['critical']}")
            print(f"    🟠 High:     {summary['by_severity']['high']}")
            print(f"    🟡 Medium:   {summary['by_severity']['medium']}")
            print(f"    🟢 Low:      {summary['by_severity']['low']}")
    else:
        # Count how many have versions
        with_version = sum(1 for t in techs if t.get('version'))
        print(f"  Versions found: {with_version}/{len(techs)}")


def main():
    """Main function - entry point of the program"""
    
    print_banner()
    
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='TechScan - Security-focused technology stack analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://example.com           # Scan a live URL
  python main.py --demo wordpress              # Use demo data
  python main.py https://example.com --online  # Use real-time CVE APIs
  python main.py --demo wordpress --online     # Demo with live APIs

Available demo sites: wordpress, react, angular, vue, laravel
        """
    )
    
    parser.add_argument('url', nargs='?', help='URL to scan')
    parser.add_argument('--demo', metavar='SITE', help='Use demo site instead of URL')
    parser.add_argument('--online', action='store_true', 
                        help='Use real-time vulnerability APIs (requires internet)')
    parser.add_argument('--nvd-key', metavar='KEY',
                        help='NVD API key for higher rate limits')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.url and not args.demo:
        parser.print_help()
        sys.exit(1)
    
    # Create detector
    detector = TechDetector()
    
    # Run scan
    if args.demo:
        result = detector.scan_demo(args.demo)
    else:
        result = detector.scan(args.url)
    
    # If scan succeeded, check for vulnerabilities
    vuln_results = None
    summary = None
    
    if result['status'] == 'success' and result['technologies']:
        
        # Choose vulnerability checker based on --online flag
        if args.online:
            if not ONLINE_AVAILABLE:
                print("⚠️  Online mode requires 'requests' library")
                print("   Falling back to offline mode...")
                vuln_checker = VulnerabilityChecker()
            else:
                print("🌐 Using REAL-TIME vulnerability APIs (OSV + NVD)")
                print("   This may take a moment...\n")
                vuln_checker = RealTimeVulnChecker(
                    nvd_api_key=args.nvd_key,
                    use_nvd=True,
                    use_osv=True
                )
        else:
            print("📁 Using LOCAL vulnerability database")
            print("   (Use --online for real-time CVE data)\n")
            vuln_checker = VulnerabilityChecker()
        
        print("🔍 Checking for vulnerabilities...")
        vuln_results = vuln_checker.check_all(result['technologies'])
        
        # Generate summary (works for both checkers)
        if hasattr(vuln_checker, 'get_summary'):
            summary = vuln_checker.get_summary(vuln_results)
        else:
            # Manual summary for real-time checker
            total_vulns = sum(t.get('vuln_count', 0) for t in vuln_results)
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for tech in vuln_results:
                for vuln in tech.get('vulnerabilities', []):
                    sev = vuln.get('severity', 'unknown')
                    if sev in severity_counts:
                        severity_counts[sev] += 1
            
            summary = {
                'total_technologies': len(vuln_results),
                'technologies_with_vulns': sum(1 for t in vuln_results if t.get('vuln_count', 0) > 0),
                'technologies_safe': sum(1 for t in vuln_results if t.get('vuln_count', 0) == 0),
                'total_vulnerabilities': total_vulns,
                'by_severity': severity_counts
            }
    
    # Print results
    print_results(result, vuln_results, summary)
    
    # Return the result for programmatic use
    return {
        'scan': result,
        'vulnerabilities': vuln_results,
        'summary': summary
    }


if __name__ == "__main__":
    main()