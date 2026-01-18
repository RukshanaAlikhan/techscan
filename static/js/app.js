/**
 * TechScan - Frontend JavaScript
 * Handles user interactions and API communication
 */

// DOM Elements
const urlInput = document.getElementById('urlInput');
const scanBtn = document.getElementById('scanBtn');
const onlineMode = document.getElementById('onlineMode');
const loadingState = document.getElementById('loadingState');
const loadingMessage = document.getElementById('loadingMessage');
const errorState = document.getElementById('errorState');
const errorMessage = document.getElementById('errorMessage');
const retryBtn = document.getElementById('retryBtn');
const resultsSection = document.getElementById('resultsSection');
const newScanBtn = document.getElementById('newScanBtn');

// Loading steps
const steps = ['step1', 'step2', 'step3', 'step4'];

// State
let currentUrl = '';

/**
 * Initialize the application
 */
function init() {
    // Event listeners
    scanBtn.addEventListener('click', startScan);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') startScan();
    });
    retryBtn.addEventListener('click', startScan);
    newScanBtn.addEventListener('click', resetScanner);
    
    // Focus input on load
    urlInput.focus();
}

/**
 * Start the scanning process
 */
async function startScan() {
    const url = urlInput.value.trim();
    
    if (!url) {
        shakeInput();
        return;
    }
    
    currentUrl = url;
    
    // Show loading state
    showLoading();
    
    try {
        // Animate through steps
        await animateStep(0, 'Connecting to target...');
        await animateStep(1, 'Analyzing technologies...');
        
        // Make API call
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: url,
                online: onlineMode.checked
            })
        });
        
        await animateStep(2, 'Querying CVE databases...');
        
        const data = await response.json();
        
        await animateStep(3, 'Generating report...');
        
        // Small delay for UX
        await sleep(500);
        
        if (data.status === 'error') {
            showError(data.error || 'Failed to scan target');
        } else {
            showResults(data);
        }
        
    } catch (error) {
        console.error('Scan error:', error);
        showError('Network error. Please check your connection.');
    }
}

/**
 * Show loading state with animated steps
 */
function showLoading() {
    hideAll();
    loadingState.classList.remove('hidden');
    
    // Reset steps
    steps.forEach(stepId => {
        const step = document.getElementById(stepId);
        step.classList.remove('active', 'done');
        step.innerHTML = step.innerHTML.replace('◆', '◇');
    });
}

/**
 * Animate a loading step
 */
async function animateStep(index, message) {
    loadingMessage.textContent = message;
    
    // Mark previous steps as done
    for (let i = 0; i < index; i++) {
        const step = document.getElementById(steps[i]);
        step.classList.remove('active');
        step.classList.add('done');
        step.innerHTML = step.innerHTML.replace('◇', '◆');
    }
    
    // Mark current step as active
    const currentStep = document.getElementById(steps[index]);
    currentStep.classList.add('active');
    
    await sleep(600);
}

/**
 * Show error state
 */
function showError(message) {
    hideAll();
    errorMessage.textContent = message;
    errorState.classList.remove('hidden');
}

/**
 * Show results
 */
function showResults(data) {
    hideAll();
    resultsSection.classList.remove('hidden');
    
    const summary = data.summary;
    const technologies = data.technologies;
    
    // Update risk score with animation
    animateRiskScore(summary.risk_score, summary.risk_level);
    
    // Update severity breakdown
    document.getElementById('criticalCount').textContent = summary.by_severity.critical;
    document.getElementById('highCount').textContent = summary.by_severity.high;
    document.getElementById('mediumCount').textContent = summary.by_severity.medium;
    document.getElementById('lowCount').textContent = summary.by_severity.low;
    
    // Update counts
    document.getElementById('techCount').textContent = technologies.length;
    document.getElementById('vulnCount').textContent = summary.total_vulnerabilities;
    
    // Render technologies
    renderTechnologies(technologies);
    
    // Render vulnerabilities
    renderVulnerabilities(technologies);
}

/**
 * Animate the risk score gauge
 */
function animateRiskScore(score, level) {
    const scoreEl = document.getElementById('riskScore');
    const gaugeCircle = document.getElementById('gaugeCircle');
    const levelBadge = document.querySelector('.level-badge');
    
    // Animate number
    let current = 0;
    const increment = score / 30;
    const timer = setInterval(() => {
        current += increment;
        if (current >= score) {
            current = score;
            clearInterval(timer);
        }
        scoreEl.textContent = Math.round(current);
    }, 30);
    
    // Animate gauge
    const circumference = 2 * Math.PI * 80; // r=80
    const offset = circumference - (score / 100) * circumference;
    gaugeCircle.style.strokeDashoffset = offset;
    
    // Set gauge color based on level
    const colors = {
        'SAFE': '#00f5ff',
        'LOW': '#6bcf63',
        'MEDIUM': '#ffd93d',
        'HIGH': '#ff9f43',
        'CRITICAL': '#ff3e3e',
        'UNKNOWN': '#6b7280'
    };
    gaugeCircle.style.stroke = colors[level] || colors['UNKNOWN'];
    
    // Update badge
    levelBadge.textContent = level;
    levelBadge.className = 'level-badge ' + level.toLowerCase();
}

/**
 * Render technology cards
 */
function renderTechnologies(technologies) {
    const grid = document.getElementById('technologiesGrid');
    grid.innerHTML = '';
    
    technologies.forEach(tech => {
        const hasVulns = tech.vuln_count > 0;
        const card = document.createElement('div');
        card.className = `tech-card ${hasVulns ? 'has-vulns' : ''}`;
        
        card.innerHTML = `
            <div class="tech-header">
                <span class="tech-name">${escapeHtml(tech.name)}</span>
                ${tech.version ? `<span class="tech-version">v${escapeHtml(tech.version)}</span>` : ''}
            </div>
            <div class="tech-category">${escapeHtml(tech.category)}</div>
            ${hasVulns ? `<div class="tech-vuln-badge">⚠ ${tech.vuln_count} vulnerabilities</div>` : ''}
        `;
        
        grid.appendChild(card);
    });
}

/**
 * Render vulnerabilities list
 */
function renderVulnerabilities(technologies) {
    const list = document.getElementById('vulnerabilitiesList');
    const section = document.getElementById('vulnsSection');
    list.innerHTML = '';
    
    let totalVulns = 0;
    
    technologies.forEach(tech => {
        if (tech.vulnerabilities && tech.vulnerabilities.length > 0) {
            tech.vulnerabilities.forEach(vuln => {
                totalVulns++;
                const severity = (vuln.severity || 'unknown').toLowerCase();
                
                const item = document.createElement('div');
                item.className = `vuln-item ${severity}`;
                
                item.innerHTML = `
                    <div class="vuln-header">
                        <span class="vuln-id">${escapeHtml(vuln.cve_id)}</span>
                        <span class="vuln-severity ${severity}">${severity.toUpperCase()} ${vuln.cvss_score ? `(${vuln.cvss_score})` : ''}</span>
                    </div>
                    <div class="vuln-tech">Affects: ${escapeHtml(tech.name)} ${tech.version ? 'v' + escapeHtml(tech.version) : ''}</div>
                    <div class="vuln-description">${escapeHtml(vuln.description || 'No description available')}</div>
                    ${vuln.fixed_version ? `<div class="vuln-fix">→ Fix: Upgrade to v${escapeHtml(vuln.fixed_version)}</div>` : ''}
                `;
                
                list.appendChild(item);
            });
        }
    });
    
    // Hide section if no vulnerabilities
    if (totalVulns === 0) {
        section.classList.add('hidden');
    } else {
        section.classList.remove('hidden');
    }
}

/**
 * Reset scanner to initial state
 */
function resetScanner() {
    hideAll();
    urlInput.value = '';
    urlInput.focus();
}

/**
 * Hide all state sections
 */
function hideAll() {
    loadingState.classList.add('hidden');
    errorState.classList.add('hidden');
    resultsSection.classList.add('hidden');
}

/**
 * Shake input animation for validation
 */
function shakeInput() {
    const wrapper = document.querySelector('.input-wrapper');
    wrapper.style.animation = 'shake 0.5s ease';
    setTimeout(() => {
        wrapper.style.animation = '';
    }, 500);
}

/**
 * Sleep utility
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Add shake animation to CSS dynamically
const style = document.createElement('style');
style.textContent = `
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        20%, 60% { transform: translateX(-5px); }
        40%, 80% { transform: translateX(5px); }
    }
`;
document.head.appendChild(style);

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', init);