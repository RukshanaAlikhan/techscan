"""
detector.py - Technology Detection Module (Enhanced)

This module detects technologies using Wappalyzer-compatible signatures.
Supports 6,000+ technologies when using updated signatures.

Detection methods:
- HTTP headers
- HTML content patterns
- Script sources
- Meta tags
- Cookies
- CSS patterns
"""

import requests
from bs4 import BeautifulSoup
import json
import re
from pathlib import Path


class TechDetector:
    """
    Enhanced technology detector supporting Wappalyzer signatures.
    """
    
    def __init__(self, signatures_path=None):
        """Initialize the detector with technology signatures."""
        if signatures_path is None:
            base_dir = Path(__file__).parent.parent
            signatures_path = base_dir / "signatures" / "technologies.json"
        
        self.signatures = self._load_signatures(signatures_path)
        self.detected_techs = []
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        
        print(f"📚 Loaded {len(self.signatures)} technology signatures")
    
    def _load_signatures(self, path):
        """Load technology signatures from JSON file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('technologies', {})
        except FileNotFoundError:
            print(f"⚠️  Signatures file not found: {path}")
            return {}
        except json.JSONDecodeError as e:
            print(f"⚠️  Invalid JSON in signatures file: {e}")
            return {}
    
    def scan(self, url):
        """
        Scan a URL for technologies.
        
        Args:
            url: The website URL to scan
            
        Returns:
            dict: Scan results including detected technologies
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"\n🔍 Scanning: {url}\n")
        
        self.detected_techs = []
        
        try:
            response = requests.get(
                url, 
                headers=self.headers, 
                timeout=15,
                allow_redirects=True,
                verify=True
            )
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Collect all script sources
            scripts = []
            for script in soup.find_all('script', src=True):
                scripts.append(script.get('src', ''))
            
            # Collect all CSS links
            css_links = []
            for link in soup.find_all('link', rel='stylesheet'):
                css_links.append(link.get('href', ''))
            
            page_data = {
                'url': url,
                'status_code': response.status_code,
                'headers': {k.lower(): v for k, v in response.headers.items()},
                'html': response.text,
                'soup': soup,
                'cookies': response.cookies.get_dict(),
                'scripts': scripts,
                'css': css_links,
            }
            
            # Run detection
            detected_count = 0
            for tech_id, tech_info in self.signatures.items():
                result = self._detect_technology(tech_id, tech_info, page_data)
                if result:
                    self.detected_techs.append(result)
                    detected_count += 1
            
            print(f"✅ Detected {detected_count} technologies")
            
            return {
                'url': url,
                'status': 'success',
                'technologies': self.detected_techs
            }
            
        except requests.exceptions.Timeout:
            return {'url': url, 'status': 'error', 'error': 'Connection timed out', 'technologies': []}
        except requests.exceptions.SSLError:
            return {'url': url, 'status': 'error', 'error': 'SSL certificate error', 'technologies': []}
        except requests.exceptions.ConnectionError:
            return {'url': url, 'status': 'error', 'error': 'Could not connect to server', 'technologies': []}
        except requests.exceptions.RequestException as e:
            return {'url': url, 'status': 'error', 'error': str(e), 'technologies': []}
    
    def _detect_technology(self, tech_id, tech_info, page_data):
        """
        Check if a specific technology is present.
        
        Returns tech dict if detected, None otherwise.
        """
        detection = tech_info.get('detection', {})
        detected = False
        confidence = 0
        version = None
        
        # Check Headers
        if 'headers' in detection:
            for header_name, pattern in detection['headers'].items():
                header_value = page_data['headers'].get(header_name.lower(), '')
                if self._match_pattern(pattern, header_value):
                    detected = True
                    confidence += 30
                    version = version or self._extract_version(pattern, header_value)
        
        # Check HTML patterns
        if 'html' in detection:
            for pattern in detection['html']:
                if self._match_pattern(pattern, page_data['html']):
                    detected = True
                    confidence += 20
                    version = version or self._extract_version(pattern, page_data['html'])
        
        # Check Script sources
        if 'scripts' in detection:
            for pattern in detection['scripts']:
                for script_src in page_data['scripts']:
                    if self._match_pattern(pattern, script_src):
                        detected = True
                        confidence += 25
                        version = version or self._extract_version(pattern, script_src)
        
        # Check Meta tags
        if 'meta' in detection:
            soup = page_data['soup']
            for meta_name, pattern in detection['meta'].items():
                meta_tag = soup.find('meta', attrs={'name': meta_name})
                if not meta_tag:
                    meta_tag = soup.find('meta', attrs={'property': meta_name})
                if meta_tag:
                    content = meta_tag.get('content', '')
                    if self._match_pattern(pattern, content):
                        detected = True
                        confidence += 30
                        version = version or self._extract_version(pattern, content)
        
        # Check Cookies
        if 'cookies' in detection:
            cookie_names = [c.lower() for c in page_data['cookies'].keys()]
            for cookie_pattern in detection['cookies']:
                if isinstance(cookie_pattern, str):
                    if cookie_pattern.lower() in cookie_names:
                        detected = True
                        confidence += 20
        
        # Check CSS
        if 'css' in detection:
            for pattern in detection['css']:
                # Check in CSS links
                for css_link in page_data['css']:
                    if self._match_pattern(pattern, css_link):
                        detected = True
                        confidence += 15
                # Check in HTML (inline styles)
                if self._match_pattern(pattern, page_data['html']):
                    detected = True
                    confidence += 10
        
        if detected:
            return {
                'id': tech_id,
                'name': tech_info.get('name', tech_id),
                'category': tech_info.get('category', 'Unknown'),
                'version': version,
                'website': tech_info.get('website', ''),
                'confidence': min(confidence, 100),
                'cpe': tech_info.get('cpe', ''),  # For CVE matching
            }
        
        return None
    
    def _match_pattern(self, pattern, text):
        """
        Match a Wappalyzer-style pattern against text.
        
        Wappalyzer patterns can include:
        - Regular text (case-insensitive match)
        - Regex patterns
        - Version extraction: \\;version:\\1
        """
        if not pattern or not text:
            return False
        
        # Handle string patterns
        if isinstance(pattern, str):
            # Remove version extraction part for matching
            clean_pattern = pattern.split('\\;')[0].split(';version:')[0]
            
            # If it looks like a regex
            if any(c in clean_pattern for c in ['\\', '[', ']', '(', ')', '*', '+', '?', '^', '$', '|']):
                try:
                    return bool(re.search(clean_pattern, text, re.IGNORECASE))
                except re.error:
                    # Invalid regex, try literal match
                    return clean_pattern.lower() in text.lower()
            else:
                # Simple string match
                return clean_pattern.lower() in text.lower()
        
        # Handle dict patterns (Wappalyzer format)
        elif isinstance(pattern, dict):
            # Check if any key matches
            for key, value in pattern.items():
                if self._match_pattern(value, text):
                    return True
        
        return False
    
    def _extract_version(self, pattern, text):
        """
        Extract version number from text using Wappalyzer pattern.
        
        Patterns like: "jquery-([0-9.]+)\\.js\\;version:\\1"
        """
        if not pattern or not text:
            return None
        
        if isinstance(pattern, str):
            # Check for version extraction syntax
            clean_pattern = pattern.split('\\;version:')[0].split(';version:')[0]
            
            # Try to find version in the pattern's capture group
            try:
                match = re.search(clean_pattern, text, re.IGNORECASE)
                if match and match.groups():
                    version = match.group(1)
                    # Clean up version string
                    version = re.sub(r'[^\d.]', '', version)
                    if version and version[0].isdigit():
                        return version
            except (re.error, IndexError):
                pass
            
            # Fallback: try common version patterns
            version_patterns = [
                r'[/\-_]v?(\d+\.\d+(?:\.\d+)?)',  # /v1.2.3, -1.2.3
                r'version["\s:=]+["\']?(\d+\.\d+(?:\.\d+)?)',  # version: "1.2.3"
            ]
            
            for vp in version_patterns:
                match = re.search(vp, text, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        return None
    
    def scan_demo(self, demo_name):
        """Scan a demo site (for testing without network)."""
        from .demo import get_demo_site, list_demo_sites
        
        demo_data = get_demo_site(demo_name)
        
        if not demo_data:
            return {
                'url': f'demo://{demo_name}',
                'status': 'error',
                'error': f"Unknown demo site. Available: {', '.join(list_demo_sites())}",
                'technologies': []
            }
        
        print(f"\n🔍 Scanning demo site: {demo_name}\n")
        
        self.detected_techs = []
        
        soup = BeautifulSoup(demo_data['html'], 'html.parser')
        
        scripts = [s.get('src', '') for s in soup.find_all('script', src=True)]
        css_links = [l.get('href', '') for l in soup.find_all('link', rel='stylesheet')]
        
        page_data = {
            'url': f'demo://{demo_name}',
            'status_code': 200,
            'headers': {k.lower(): v for k, v in demo_data['headers'].items()},
            'html': demo_data['html'],
            'soup': soup,
            'cookies': demo_data.get('cookies', {}),
            'scripts': scripts,
            'css': css_links,
        }
        
        for tech_id, tech_info in self.signatures.items():
            result = self._detect_technology(tech_id, tech_info, page_data)
            if result:
                self.detected_techs.append(result)
        
        return {
            'url': f'demo://{demo_name}',
            'status': 'success',
            'technologies': self.detected_techs
        }


if __name__ == "__main__":
    detector = TechDetector()
    
    print("\nTesting with demo WordPress site...")
    result = detector.scan_demo("wordpress")
    
    print(f"\n📋 Results ({len(result['technologies'])} technologies):")
    for tech in result['technologies']:
        version_str = f" v{tech['version']}" if tech['version'] else ""
        print(f"  • {tech['name']}{version_str} ({tech['category']}) - {tech['confidence']}% confidence")
