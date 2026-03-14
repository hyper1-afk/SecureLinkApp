// SecureLink Popup Script

document.addEventListener('DOMContentLoaded', () => {
    const urlInput      = document.getElementById('url-input');
    const checkBtn      = document.getElementById('check-btn');
    const resultEl      = document.getElementById('result');
    const resultIcon    = document.getElementById('result-icon');
    const resultText    = document.getElementById('result-text');
    const resultScore   = document.getElementById('result-score');
    const resultThreats = document.getElementById('result-threats');
    const checkedCount   = document.getElementById('checked-count');
    const blockedCount   = document.getElementById('blocked-count');
    const safeCount      = document.getElementById('safe-count');
    const clearBadgeBtn  = document.getElementById('clear-badge-btn');

    const loginSection  = document.getElementById('login-section');
    const userSection   = document.getElementById('user-section');
    const loginEmail    = document.getElementById('login-email');
    const loginPassword = document.getElementById('login-password');
    const loginBtn      = document.getElementById('login-btn');
    const loginError    = document.getElementById('login-error');
    const logoutBtn     = document.getElementById('logout-btn');
    const userEmailEl   = document.getElementById('user-email');
    const userPlanEl    = document.getElementById('user-plan');
    const userAvatar    = document.getElementById('user-avatar');
    const tierBadge     = document.getElementById('tier-badge');
    const statusText    = document.getElementById('status-text');
    const statusDot     = document.getElementById('status-dot');

    loadStats();
    checkLoginStatus();
    loadLastScanResult();

    clearBadgeBtn.addEventListener('click', function() {
        chrome.runtime.sendMessage({ action: 'clearBadge' }, function() {
            blockedCount.textContent = '0';
            safeCount.textContent = Math.max(0, parseInt(checkedCount.textContent) - 0);
            clearBadgeBtn.classList.remove('visible');
        });
    });

    loginBtn.addEventListener('click', handleLogin);
    loginPassword.addEventListener('keydown', function(e) { if (e.key === 'Enter') handleLogin(); });
    logoutBtn.addEventListener('click', handleLogout);
    checkBtn.addEventListener('click', runScan);
    urlInput.addEventListener('keydown', function(e) { if (e.key === 'Enter') runScan(); });

    function loadLastScanResult() {
        chrome.storage.local.get(['lastScanResult'], function(data) {
            if (!data.lastScanResult) return;
            applyLastScanResult(data.lastScanResult);
        });
    }

    function applyLastScanResult(r) {
        if (!r || Date.now() - r.timestamp > 5 * 60 * 1000) return;
        urlInput.value = r.url || '';

        if (r.status === 'scanning') {
            showResult('scanning', '…', 'Scanning', r.url, []);
        } else if (r.status === 'limit') {
            showResult('info', '!', 'Limit Reached', r.message || 'Upgrade for more scans', []);
            chrome.storage.local.remove(['lastScanResult']);
        } else if (r.status === 'done') {
            var score = r.score || 0;
            var threats = r.threats || [];
            if (score < 30) {
                showResult('safe', '✓', 'Safe', 'Risk score: ' + score + '/100', threats);
            } else if (score < 50) {
                showResult('warning', '!', 'Suspicious', 'Risk score: ' + score + '/100 — proceed with caution', threats);
            } else {
                showResult('danger', '✕', 'Threat Detected', 'Risk score: ' + score + '/100 — do not visit', threats);
            }
            loadStats();
            chrome.storage.local.remove(['lastScanResult']);
        }
    }

    // Live update when background finishes a right-click scan
    chrome.storage.onChanged.addListener(function(changes) {
        if (changes.lastScanResult && changes.lastScanResult.newValue) {
            applyLastScanResult(changes.lastScanResult.newValue);
        }
    });

    function loadStats() {
        chrome.runtime.sendMessage({ action: 'getStats' }, function(resp) {
            if (!resp) return;
            var checked = resp.checkedCount || 0;
            var blocked = resp.blockedCount || 0;
            checkedCount.textContent = checked;
            blockedCount.textContent = blocked;
            safeCount.textContent    = Math.max(0, checked - blocked);
            if (blocked > 0) {
                clearBadgeBtn.classList.add('visible');
            } else {
                clearBadgeBtn.classList.remove('visible');
            }
        });
    }

    function checkLoginStatus() {
        chrome.runtime.sendMessage({ action: 'getSession' }, function(resp) {
            if (resp && resp.session) {
                showLoggedIn(resp.session);
                chrome.runtime.sendMessage({ action: 'getStatus' }, function(status) {
                    if (status && !status.error) applyServerStatus(status);
                });
            } else {
                showLoggedOut();
            }
        });
    }

    function showLoggedIn(session) {
        loginSection.classList.add('hidden');
        userSection.classList.remove('hidden');

        var user  = session.user || {};
        var email = user.email || 'Account';
        var tier  = user.subscription_tier || 'free';

        userEmailEl.textContent = email;
        userAvatar.textContent  = email.charAt(0).toUpperCase();
        userPlanEl.textContent  = capitalize(tier) + ' plan - Unlimited scans';

        setTierBadge(tier);
        setStatus('active', 'Full Protection Active');
    }

    function showLoggedOut() {
        loginSection.classList.remove('hidden');
        userSection.classList.add('hidden');
        setTierBadge('free');
        setStatus('active', 'Protection Active');
    }

    function applyServerStatus(status) {
        var tier = status.subscription_tier || 'free';
        setTierBadge(tier);
        userPlanEl.textContent = capitalize(tier) + ' plan - Unlimited scans';
    }

    function setTierBadge(tier) {
        tierBadge.textContent = capitalize(tier);
        tierBadge.className   = 'tier-badge';
        if (tier === 'pro')        tierBadge.classList.add('pro');
        if (tier === 'enterprise') tierBadge.classList.add('enterprise');
    }

    function setStatus(type, text) {
        statusText.textContent = text;
        statusDot.className    = type === 'warning' ? 'status-dot warning' : 'status-dot';
        statusText.className   = type === 'warning' ? 'status-text status-warning' : 'status-text';
    }

    function handleLogin() {
        var email    = loginEmail.value.trim();
        var password = loginPassword.value;
        if (!email || !password) { showError('Enter your email and password.'); return; }

        loginBtn.disabled    = true;
        loginBtn.textContent = 'Signing in...';
        loginError.classList.add('hidden');

        chrome.runtime.sendMessage({ action: 'login', email: email, password: password }, function(resp) {
            loginBtn.disabled    = false;
            loginBtn.textContent = 'Sign In';
            if (resp && resp.success) {
                loginPassword.value = '';
                checkLoginStatus();
            } else {
                showError(resp && resp.error ? resp.error : 'Login failed. Check your credentials.');
            }
        });
    }

    function handleLogout() {
        chrome.runtime.sendMessage({ action: 'logout' }, function() { showLoggedOut(); });
    }

    function showError(msg) {
        loginError.textContent = msg;
        loginError.classList.remove('hidden');
    }

    function runScan() {
        var url = urlInput.value.trim();
        if (!url) return;

        if (!url.startsWith('http://') && !url.startsWith('https://')) url = 'https://' + url;
        try { new URL(url); } catch(e) {
            showResult('warning', '!', 'Invalid URL format', '', []);
            return;
        }

        checkBtn.disabled    = true;
        checkBtn.textContent = 'Scanning...';
        resultEl.classList.add('hidden');

        chrome.runtime.sendMessage({ action: 'checkUrl', url: url }, function(resp) {
            checkBtn.disabled    = false;
            checkBtn.textContent = 'Scan';

            if (!resp) { showResult('warning', '?', 'No response from scanner', '', []); return; }

            if (resp.limitReached) {
                showResult('info', '!', 'Limit reached', resp.message || 'Try again later', []);
                return;
            }

            var score   = resp.riskScore || 0;
            var threats = (resp.threats || []).concat(resp.warnings || []).slice(0, 5);

            if (score < 30) {
                showResult('safe',    'OK',  'Safe',            'Risk score: ' + score + '/100', threats);
            } else if (score < 70) {
                showResult('warning', '!',   'Suspicious',      'Risk score: ' + score + '/100 - proceed with caution', threats);
            } else {
                showResult('danger',  'X',   'Threat Detected', 'Risk score: ' + score + '/100 - do not visit', threats);
            }

            loadStats();
        });
    }

    function showResult(type, icon, text, score, threats) {
        resultEl.className      = 'result ' + type;
        resultIcon.textContent  = type === 'safe'     ? '✅' :
                                   type === 'warning'  ? '⚠️' :
                                   type === 'danger'   ? '🚨' :
                                   type === 'scanning' ? '⟳' : 'ℹ️';
        resultText.textContent  = text;
        resultScore.textContent = score;
        resultThreats.textContent = '';
        threats.forEach(function(t) {
            var tag = document.createElement('span');
            tag.className = 'threat-tag';
            tag.textContent = t;
            resultThreats.appendChild(tag);
        });
        resultEl.classList.remove('hidden');
    }

    function capitalize(str) {
        if (!str) return str;
        return str.charAt(0).toUpperCase() + str.slice(1);
    }
});
