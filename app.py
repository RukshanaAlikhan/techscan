"""
app.py - TechScan Web Interface
"""

import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from flask import Flask, render_template, request, jsonify
from techscan.detector import TechDetector
from techscan.vulns import VulnerabilityChecker

try:
    from techscan.vulns_api import RealTimeVulnChecker
    ONLINE_AVAILABLE = True
except ImportError:
    ONLINE_AVAILABLE = False

app = Flask(__name__)
detector = TechDetector()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided'}), 400
    
    url = data['url']
    use_online = data.get('online', True)
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        result = detector.scan(url)
        
        if result['status'] == 'error':
            return jsonify({
                'status': 'error',
                'error': result.get('error', 'Failed to scan URL'),
                'url': url
            })
        
        if result['technologies']:
            if use_online and ONLINE_AVAILABLE:
                vuln_checker = RealTimeVulnChecker(use_nvd=False, use_osv=True)
            else:
                vuln_checker = VulnerabilityChecker()
            
            vuln_results = vuln_checker.check_all(result['technologies'])
            
            total_vulns = sum(t.get('vuln_count', 0) for t in vuln_results)
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            for tech in vuln_results:
                for vuln in tech.get('vulnerabilities', []):
                    sev = vuln.get('severity', 'unknown').lower()
                    if sev in severity_counts:
                        severity_counts[sev] += 1
            
            risk_score = min(100, (
                severity_counts['critical'] * 25 +
                severity_counts['high'] * 15 +
                severity_counts['medium'] * 8 +
                severity_counts['low'] * 3
            ))
            
            if risk_score >= 70:
                risk_level = 'CRITICAL'
            elif risk_score >= 40:
                risk_level = 'HIGH'
            elif risk_score >= 20:
                risk_level = 'MEDIUM'
            elif risk_score > 0:
                risk_level = 'LOW'
            else:
                risk_level = 'SAFE'
            
            return jsonify({
                'status': 'success',
                'url': url,
                'technologies': vuln_results,
                'summary': {
                    'total_technologies': len(vuln_results),
                    'total_vulnerabilities': total_vulns,
                    'by_severity': severity_counts,
                    'risk_score': risk_score,
                    'risk_level': risk_level
                },
                'online_mode': use_online and ONLINE_AVAILABLE
            })
        else:
            return jsonify({
                'status': 'success',
                'url': url,
                'technologies': [],
                'summary': {
                    'total_technologies': 0,
                    'total_vulnerabilities': 0,
                    'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                    'risk_score': 0,
                    'risk_level': 'UNKNOWN'
                },
                'online_mode': use_online and ONLINE_AVAILABLE
            })
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'url': url
        }), 500


@app.route('/api/status')
def status():
    return jsonify({
        'status': 'online',
        'version': '0.1.0',
        'online_mode_available': ONLINE_AVAILABLE
    })


if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                TechScan Web Interface                   ║
    ║         Open http://localhost:5000 in your browser        ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    app.run(debug=True, host='0.0.0.0', port=5000)