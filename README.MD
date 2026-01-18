# TechScan 
TechScan is a web security scanner that works in two steps: first, it analyzes any website URL you enter and detects what technologies are being used (like WordPress, jQuery, React, Nginx, PHP, etc.) by looking at HTTP headers, HTML patterns, scripts, and cookies - similar to how Wappalyzer works. Second, it takes those detected technologies and their versions and checks them against real-time CVE databases (OSV and NVD) to find known security vulnerabilities. The tool then calculates a risk score (0-100) based on the severity of vulnerabilities found (Critical, High, Medium, Low) and displays everything in a clean dark-themed web interface. It's essentially a "security health check" for any website - enter a URL, and instantly see what's running and if it's vulnerable.


#Prerequisites

Python 3.8 or higher
Git

#Steps
1. Clone the repository: git clone https://github.com/RukshanaAlikhan/techscan.git
cd techscan
2. Install dependencies: pip install -r requirements.txt
3. Run the web app: python app.py
4. Open in browser: http://localhost:5000

Optional: Update to 6,000+ Technology Signatures
bashpython update_signatures.py
