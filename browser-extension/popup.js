// SecureLink Popup Script

document.addEventListener('DOMContentLoaded', () => {
    // Elements
    const urlInput = document.getElementById('url-input');
    const checkBtn = document.getElementById('check-btn');
    const result = document.getElementById('result');
    const resultIcon = document.getElementById('result-icon');
    const resultText = document.getElementById('result-text');
    const resultScore = document.getElementById('result-score');
    const checkedCount = document.getElementById('checked-count');
    const blockedCount = document.getElementById('blocked-count');
    
    // Login elements
    const loginSection = document.getElementById('login-section');
    const userSection = document.getElementById('user-section');
    const loginEmail = document.getElementById('login-email');
    const loginPassword = document.getElementById('login-password');
    const loginBtn = document.getElementById('login-btn');
    const loginError = document.getElementById('login-error');
    const logoutBtn = document.getElementById('logout-btn');
    const userEmailDisplay = document.getElementById('user-email');
    const scansRemaining = document.getElementById('scans-remaining');
    const tierBadge = document.getElementById('tier-badge');
    const statusText = document.getElementById('status-text');
    const statusSub = document.getElementById('status-sub');
    const upgradeCta = document.getElementById('upgrade-cta');

    // Check login status on load
    checkLoginStatus();

    // Load stats
    chrome.runtime.sendMessage({ action: 'getStats' }, (response) => {
        if (response) {
            checkedCount.textContent = response.checkedCount || 0;
            blockedCount.textContent = response.blockedCount || 0;
        }
    });

    // Login button click
    loginBtn.addEventListener('click', handleLogin);
    
    // Login on Enter key
    loginPassword.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleLogin();
    });
    
    // Logout button click
    logoutBtn.addEventListener('click', handleLogout);

    // Check URL on button click
    checkBtn.addEventListener('click', checkUrl);
    
    // Check URL on Enter key
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') checkUrl();
    });

    async function checkLoginStatus() {
        chrome.runtime.sendMessage({ action: 'getSession' }, async (response) => {
            if (response && response.session) {
                showLoggedInState(response.session);
                
                // Also fetch current status from server
                chrome.runtime.sendMessage({ action: 'getStatus' }, (status) => {
                    if (status && !status.error) {
                        updateStatusDisplay(status);
                    }
                });
            } else {
                showLoggedOutState();
            }
        });
    }

    function showLoggedInState(session) {
        loginSection.classList.add('hidden');
        userSection.classList.remove('hidden');
        
        const user = session.user || {};
        userEmailDisplay.textContent = user.email || 'User';
        
        // Update tier badge
        const tier = user.subscription_tier || 'free';
        tierBadge.textContent = tier.charAt(0).toUpperCase() + tier.slice(1);
        tierBadge.className = 'tier-badge';
        if (tier === 'pro') tierBadge.classList.add('pro');
        if (tier === 'enterprise') tierBadge.classList.add('enterprise');
        
        // Update scans display
        if (session.scanLimit === 'unlimited' || tier === 'enterprise') {
            scansRemaining.textContent = 'Unlimited scans';
            updateScanTracker(0, 'unlimited');
        } else {
            const limit = session.scanLimit || 50;
            const used = session.scansToday || 0;
            scansRemaining.textContent = `${limit - used} scans remaining`;
            updateScanTracker(used, limit);
        }
        
        statusText.textContent = 'Full Protection Active';
        statusSub.textContent = 'Scanning URLs automatically';
        statusSub.className = 'status-sub';
    }

    function showLoggedOutState() {
        loginSection.classList.remove('hidden');
        userSection.classList.add('hidden');
        upgradeCta.classList.add('hidden');
        
        tierBadge.textContent = 'Free';
        tierBadge.className = 'tier-badge';
        
        statusText.textContent = 'Limited Protection';
        statusSub.textContent = '15 free scans - Sign in for 50/day';
        statusSub.className = 'status-sub warning';
        
        // Hide scan tracker when logged out
        const scanTracker = document.getElementById('scan-tracker');
        if (scanTracker) scanTracker.style.display = 'none';
    }

    function updateStatusDisplay(status) {
        const tier = status.subscription_tier || 'free';
        
        // Update tier badge
        tierBadge.textContent = tier.charAt(0).toUpperCase() + tier.slice(1);
        tierBadge.className = 'tier-badge';
        if (tier === 'pro') tierBadge.classList.add('pro');
        if (tier === 'enterprise') tierBadge.classList.add('enterprise');
        
        // Update scans remaining and tracker
        if (status.scan_limit === 'unlimited') {
            scansRemaining.textContent = 'Unlimited scans';
            upgradeCta.classList.add('hidden');
            updateScanTracker(0, 'unlimited');
        } else {
            const remaining = status.scans_remaining || 0;
            const limit = status.scan_limit || 50;
            const used = status.scans_today || (limit - remaining);
            scansRemaining.textContent = `${remaining} scans remaining`;
            updateScanTracker(used, limit);
            
            // Show upgrade CTA if running low
            if (remaining <= 5 && tier === 'free') {
                upgradeCta.classList.remove('hidden');
            } else {
                upgradeCta.classList.add('hidden');
            }
        }
    }

    function updateScanTracker(used, limit) {
        const scanTracker = document.getElementById('scan-tracker');
        const scanCount = document.getElementById('scan-count');
        const scanProgress = document.getElementById('scan-progress');
        const scanResetTime = document.getElementById('scan-reset-time');
        
        if (!scanTracker) return;
        
        // Show tracker for logged-in users
        scanTracker.style.display = 'block';
        
        if (limit === 'unlimited') {
            scanTracker.classList.add('unlimited');
            scanCount.textContent = `${used} scans today`;
            scanProgress.style.width = '0%';
            scanResetTime.textContent = 'Unlimited plan';
        } else {
            scanTracker.classList.remove('unlimited');
            scanCount.textContent = `${used} / ${limit}`;
            
            const percentage = Math.min((used / limit) * 100, 100);
            scanProgress.style.width = `${percentage}%`;
            
            // Color code based on usage
            scanProgress.classList.remove('warning', 'danger');
            if (percentage >= 90) {
                scanProgress.classList.add('danger');
            } else if (percentage >= 70) {
                scanProgress.classList.add('warning');
            }
            
            // Calculate time until midnight reset
            const now = new Date();
            const midnight = new Date(now);
            midnight.setHours(24, 0, 0, 0);
            const hoursUntilReset = Math.ceil((midnight - now) / (1000 * 60 * 60));
            scanResetTime.textContent = `Resets in ${hoursUntilReset} hour${hoursUntilReset !== 1 ? 's' : ''}`;
        }
    }

    async function handleLogin() {
        const email = loginEmail.value.trim();
        const password = loginPassword.value;
        
        if (!email || !password) {
            showLoginError('Please enter email and password');
            return;
        }
        
        loginBtn.disabled = true;
        loginBtn.textContent = 'Signing in...';
        loginError.style.display = 'none';
        
        chrome.runtime.sendMessage({ 
            action: 'login',
            email: email,
            password: password
        }, (response) => {
            loginBtn.disabled = false;
            loginBtn.textContent = 'Sign In';
            
            if (response && response.success) {
                loginPassword.value = '';
                checkLoginStatus();
            } else {
                showLoginError(response?.error || 'Login failed');
            }
        });
    }

    function handleLogout() {
        chrome.runtime.sendMessage({ action: 'logout' }, (response) => {
            showLoggedOutState();
        });
    }

    function showLoginError(message) {
        loginError.textContent = message;
        loginError.style.display = 'block';
    }

    async function checkUrl() {
        let url = urlInput.value.trim();
        
        if (!url) {
            showResult('warning', '⚠️', 'Please enter a URL', '');
            return;
        }

        // Add https:// if no protocol
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }

        // Validate URL
        try {
            new URL(url);
        } catch (e) {
            showResult('warning', '⚠️', 'Invalid URL format', '');
            return;
        }

        checkBtn.disabled = true;
        checkBtn.textContent = '...';

        try {
            const response = await chrome.runtime.sendMessage({ 
                action: 'checkUrl', 
                url: url 
            });

            if (response) {
                // Handle rate limit
                if (response.limitReached) {
                    showResult('limit', '⏳', 'Scan limit reached', response.message || 'Upgrade for more scans');
                    return;
                }
                
                const score = response.riskScore || 0;
                
                // Update scans remaining if provided
                if (response.scansRemaining !== undefined) {
                    scansRemaining.textContent = response.scansRemaining + ' scans remaining today';
                }
                
                if (score < 30) {
                    showResult('safe', '✅', 'Safe', `Risk Score: ${score}/100`);
                } else if (score < 70) {
                    showResult('warning', '⚠️', 'Suspicious', `Risk Score: ${score}/100 - Proceed with caution`);
                } else {
                    showResult('danger', '🚨', 'Dangerous!', `Risk Score: ${score}/100 - Do not visit this site`);
                }
            } else {
                showResult('warning', '❓', 'Could not verify', 'Try again later');
            }
        } catch (error) {
            console.error('Error:', error);
            showResult('warning', '❌', 'Error checking URL', error.message);
        }

        checkBtn.disabled = false;
        checkBtn.textContent = 'Check';
    }

    function showResult(type, icon, text, score) {
        result.className = 'result ' + type;
        result.style.display = 'block';
        resultIcon.textContent = icon;
        resultText.textContent = text;
        resultScore.textContent = score;
    }
});

