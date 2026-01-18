"""
detector.py - Technology Detection Module

This module is responsible for:
1. Fetching a webpage
2. Analyzing headers, HTML, scripts, and meta tags
3. Matching against our signature database

LEARNING NOTES:
- We use 'requests' library to fetch web pages
- BeautifulSoup helps us parse HTML easily
- We look for "fingerprints" - unique patterns that identify technologies
"""

import requests
from bs4 import BeautifulSoup
import json
import re
from pathlib import Path


class TechDetector:
    """
    Main class for detecting technologies on a website.
    
    How it works:
    1. Fetch the target URL
    2. Extract useful data (headers, HTML, scripts, etc.)
    3. Compare against known signatures
    4. Return list of detected technologies
    """
    
    def __init__(self, signatures_path=None):
        """
        Initialize the detector with technology signatures.
        
        Args:
            signatures_path: Path to the JSON file containing tech signatures
        """
        # If no path provided, use default location
        if signatures_path is None:
            # __file__ gives us this script's location
            # We go up one level and into signatures folder
            base_dir = Path(__file__).parent.parent
            signatures_path = base_dir / "signatures" / "technologies.json"
        
        # Load our signature database
        self.signatures = self._load_signatures(signatures_path)
        
        # Store results here
        self.detected_techs = []
        
        # User-Agent header makes us look like a real browser
        # Some websites block requests without this
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    
    def _load_signatures(self, path):
        """
        Load technology signatures from JSON file.
        
        This is like loading a "dictionary" of fingerprints that help us
        identify different technologies.
        """
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                return data.get('technologies', {})
        except FileNotFoundError:
            print(f"Signatures file not found: {path}")
            return {}
        except json.JSONDecodeError:
            print(f"Invalid JSON in signatures file")
            return {}
    
    def scan(self, url):
        """
        Main method - scan a URL for technologies.
        
        Args:
            url: The website URL to scan (e.g., "https://example.com")
            
        Returns:
            dict: Scan results including detected technologies
        """
        # Make sure URL has a scheme (http:// or https://)
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"\n Scanning: {url}\n")
        
        # Reset detected technologies
        self.detected_techs = []
        
        try:
            # Step 1 Fetch the webpage
            # timeout=10 means wait max 10 seconds for response
            response = requests.get(url, headers=self.headers, timeout=10)
            
            # Step 2 Parse the HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Step 3 Extract useful data for analysis
            page_data = {
                'url': url,
                'status_code': response.status_code,
                'headers': dict(response.headers),  # HTTP headers
                'html': response.text,               # Raw HTML
                'soup': soup,                        # Parsed HTML
                'cookies': response.cookies.get_dict()  # Cookies
            }
            
            # Step 4 Run detection for each technology
            for tech_id, tech_info in self.signatures.items():
                if self._detect_technology(tech_id, tech_info, page_data):
                    # Technology detected! Try to find version too
                    version = self._detect_version(tech_id, tech_info, page_data)
                    
                    self.detected_techs.append({
                        'id': tech_id,
                        'name': tech_info.get('name', tech_id),
                        'category': tech_info.get('category', 'Unknown'),
                        'version': version,
                        'website': tech_info.get('website', '')
                    })
            
            return {
                'url': url,
                'status': 'success',
                'technologies': self.detected_techs
            }
            
        except requests.exceptions.RequestException as e:
            # Handle network errors gracefully
            return {
                'url': url,
                'status': 'error',
                'error': str(e),
                'technologies': []
            }
    
    def _detect_technology(self, tech_id, tech_info, page_data):
        """
        Check if a specific technology is present on the page.
        
        We check multiple indicators:
        - HTTP headers (Server, X-Powered-By, etc.)
        - HTML content (specific strings, patterns)
        - Script tags (JavaScript libraries)
        - Meta tags (generator, etc.)
        - Cookies
        
        Returns True if technology is detected, False otherwise.
        """
        detection = tech_info.get('detection', {})
        
        # Check 1: HTTP Headers
        # Some servers reveal what they're running in headers
        if 'headers' in detection:
            for header_name, header_value in detection['headers'].items():
                actual_value = page_data['headers'].get(header_name, '')
                if header_value:
                    # Looking for specific value in header
                    if header_value.lower() in actual_value.lower():
                        return True
                else:
                    # Just checking if header exists
                    if header_name.lower() in [h.lower() for h in page_data['headers']]:
                        return True
        
        # Check 2: HTML Content
        # Look for specific strings in the HTML
        if 'html' in detection:
            html_lower = page_data['html'].lower()
            for pattern in detection['html']:
                if pattern.lower() in html_lower:
                    return True
        
        # Check 3: Script Tags
        # Check src attributes of <script> tags
        if 'scripts' in detection:
            soup = page_data['soup']
            script_tags = soup.find_all('script', src=True)
            for script in script_tags:
                src = script.get('src', '').lower()
                for pattern in detection['scripts']:
                    if pattern.lower() in src:
                        return True
        
        # Check 4: Meta Tags
        # e.g., <meta name="generator" content="WordPress 6.0">
        if 'meta' in detection:
            soup = page_data['soup']
            for meta_name, meta_value in detection['meta'].items():
                meta_tag = soup.find('meta', attrs={'name': meta_name})
                if meta_tag:
                    content = meta_tag.get('content', '')
                    if meta_value.lower() in content.lower():
                        return True
        
        # Check 5: Cookies
        # Some frameworks set specific cookies
        if 'cookies' in detection:
            for cookie_name in detection['cookies']:
                if cookie_name.lower() in [c.lower() for c in page_data['cookies']]:
                    return True
        
        return False
    
    def _detect_version(self, tech_id, tech_info, page_data):
        """
        Try to extract the version number of a detected technology.
        
        This is trickier than detection - not all technologies expose versions.
        
        Common version sources:
        - HTTP headers: "Server: nginx/1.18.0"
        - Meta tags: <meta name="generator" content="WordPress 6.0">
        - Script filenames: jquery-3.6.0.min.js
        - Script content: /* jQuery v3.6.0 */
        """
        version_info = tech_info.get('version_detection', {})
        
        if not version_info:
            return None
        
        # Try each version detection method
        
        # Method 1: From HTTP headers
        if 'header' in version_info:
            pattern = version_info['header']
            # Check common headers that might contain version
            for header_name in ['server', 'x-powered-by']:
                header_value = page_data['headers'].get(header_name, '')
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        # Method 2: From meta generator tag
        if 'meta_generator' in version_info:
            pattern = version_info['meta_generator']
            soup = page_data['soup']
            meta_tag = soup.find('meta', attrs={'name': 'generator'})
            if meta_tag:
                content = meta_tag.get('content', '')
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        # Method 3: From script filename
        if 'script_filename' in version_info:
            pattern = version_info['script_filename']
            soup = page_data['soup']
            script_tags = soup.find_all('script', src=True)
            for script in script_tags:
                src = script.get('src', '')
                match = re.search(pattern, src, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        # Method 4: From CSS filename
        if 'css_filename' in version_info:
            pattern = version_info['css_filename']
            soup = page_data['soup']
            link_tags = soup.find_all('link', rel='stylesheet')
            for link in link_tags:
                href = link.get('href', '')
                match = re.search(pattern, href, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        # Method 5: From HTML attributes (like ng-version for Angular)
        if 'html_attribute' in version_info:
            pattern = version_info['html_attribute']
            match = re.search(pattern, page_data['html'])
            if match:
                return match.group(1)
        
        return None


    def scan_demo(self, demo_name):
        """
        Scan a demo site (for testing without network).
        
        Args:
            demo_name: Name of demo site ('wordpress', 'react', etc.)
            
        Returns:
            dict: Scan results
        """
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
        
        # Reset detected technologies
        self.detected_techs = []
        
        # Parse HTML for the demo
        soup = BeautifulSoup(demo_data['html'], 'html.parser')
        
        # Build page_data from demo
        page_data = {
            'url': f'demo://{demo_name}',
            'status_code': 200,
            'headers': demo_data['headers'],
            'html': demo_data['html'],
            'soup': soup,
            'cookies': demo_data.get('cookies', {})
        }
        
        # Run detection
        for tech_id, tech_info in self.signatures.items():
            if self._detect_technology(tech_id, tech_info, page_data):
                version = self._detect_version(tech_id, tech_info, page_data)
                
                self.detected_techs.append({
                    'id': tech_id,
                    'name': tech_info.get('name', tech_id),
                    'category': tech_info.get('category', 'Unknown'),
                    'version': version,
                    'website': tech_info.get('website', '')
                })
        
        return {
            'url': f'demo://{demo_name}',
            'status': 'success',
            'technologies': self.detected_techs
        }


# This allows us to test the module directly
if __name__ == "__main__":
    # Quick test with demo mode
    detector = TechDetector()
    
    print("Testing with demo WordPress site...")
    result = detector.scan_demo("wordpress")
    
    print("\n📋 Results:")
    for tech in result['technologies']:
        version_str = f" v{tech['version']}" if tech['version'] else ""
        print(f"  • {tech['name']}{version_str} ({tech['category']})")