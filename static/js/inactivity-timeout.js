/**
 * SecureLink Inactivity Timeout
 * Automatically logs the user out after 30 minutes of inactivity.
 * 
 * "Activity" = any mouse movement, click, scroll, keypress, or touch event.
 * A warning modal appears 2 minutes before logout so the user can extend.
 *
 * Include this script on every authenticated page:
 *   <script src="/static/js/inactivity-timeout.js"></script>
 */
(function () {
    'use strict';

    const TIMEOUT_MS       = 30 * 60 * 1000;   // 30 minutes
    const WARNING_BEFORE   =  2 * 60 * 1000;   // show warning 2 min before logout
    const WARNING_AT       = TIMEOUT_MS - WARNING_BEFORE; // 28 min

    let inactivityTimer  = null;
    let warningTimer     = null;
    let warningShown     = false;

    // ── Helpers ──────────────────────────────────────────────────
    function getAuthToken() {
        return localStorage.getItem('auth_token');
    }

    function performLogout() {
        // Tell the server to invalidate the session
        const token = getAuthToken();
        if (token) {
            navigator.sendBeacon('/api/auth/logout', new Blob(
                [JSON.stringify({})],
                { type: 'application/json' }
            ));
            // sendBeacon doesn't support custom headers, so also try fetch
            fetch('/api/auth/logout', {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + token,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({})
            }).catch(function () { /* ignore */ });
        }
        localStorage.removeItem('auth_token');
        localStorage.removeItem('user');
        window.location.href = '/login?reason=inactivity';
    }

    // ── Warning modal ────────────────────────────────────────────
    function createWarningModal() {
        if (document.getElementById('inactivity-warning-modal')) return;

        const overlay = document.createElement('div');
        overlay.id = 'inactivity-warning-modal';
        overlay.innerHTML = `
            <div style="
                position:fixed;inset:0;background:rgba(0,0,0,.65);
                display:flex;align-items:center;justify-content:center;z-index:100000;">
                <div style="
                    background:#1e293b;color:#f8fafc;padding:32px 36px;border-radius:16px;
                    max-width:420px;width:90%;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.5);
                    font-family:'Segoe UI',Arial,sans-serif;">
                    <div style="font-size:40px;margin-bottom:12px;">⏳</div>
                    <h2 style="margin:0 0 8px;font-size:20px;color:#f8fafc;">Session Expiring Soon</h2>
                    <p style="color:#94a3b8;margin:0 0 20px;font-size:15px;line-height:1.5;">
                        You've been inactive for a while. For your security, you'll be signed out in
                        <strong id="inactivity-countdown" style="color:#f59e0b;">2:00</strong>.
                    </p>
                    <button id="inactivity-stay-btn" style="
                        background:linear-gradient(135deg,#0ea5e9,#0284c7);color:#fff;border:none;
                        padding:12px 32px;border-radius:10px;font-size:15px;font-weight:600;
                        cursor:pointer;margin-right:8px;">Stay Signed In</button>
                    <button id="inactivity-logout-btn" style="
                        background:transparent;color:#94a3b8;border:1px solid #334155;
                        padding:12px 24px;border-radius:10px;font-size:15px;cursor:pointer;">Sign Out</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);

        document.getElementById('inactivity-stay-btn').addEventListener('click', function () {
            dismissWarning();
            resetTimers();
            // Touch the server to refresh last_used
            const token = getAuthToken();
            if (token) {
                fetch('/api/auth/validate', {
                    headers: { 'Authorization': 'Bearer ' + token }
                }).catch(function () {});
            }
        });
        document.getElementById('inactivity-logout-btn').addEventListener('click', function () {
            performLogout();
        });

        // Countdown
        let remaining = WARNING_BEFORE / 1000; // seconds
        const countdownEl = document.getElementById('inactivity-countdown');
        const countdownInterval = setInterval(function () {
            remaining--;
            if (remaining <= 0) {
                clearInterval(countdownInterval);
                performLogout();
                return;
            }
            const m = Math.floor(remaining / 60);
            const s = remaining % 60;
            countdownEl.textContent = m + ':' + (s < 10 ? '0' : '') + s;
        }, 1000);

        overlay._countdownInterval = countdownInterval;
        warningShown = true;
    }

    function dismissWarning() {
        const modal = document.getElementById('inactivity-warning-modal');
        if (modal) {
            clearInterval(modal._countdownInterval);
            modal.remove();
        }
        warningShown = false;
    }

    // ── Timer management ─────────────────────────────────────────
    function resetTimers() {
        clearTimeout(warningTimer);
        clearTimeout(inactivityTimer);

        if (warningShown) {
            dismissWarning();
        }

        // Only run if the user is actually logged in
        if (!getAuthToken()) return;

        warningTimer = setTimeout(function () {
            createWarningModal();
        }, WARNING_AT);

        inactivityTimer = setTimeout(function () {
            performLogout();
        }, TIMEOUT_MS);
    }

    // ── Activity listeners ───────────────────────────────────────
    var ACTIVITY_EVENTS = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart', 'click'];

    // Throttle: only reset timers at most once every 30 seconds to avoid performance impact
    var lastReset = 0;
    function onActivity() {
        var now = Date.now();
        if (now - lastReset < 30000) return;
        lastReset = now;
        resetTimers();
    }

    // ── Initialise ───────────────────────────────────────────────
    function init() {
        if (!getAuthToken()) return; // not logged in — nothing to do

        ACTIVITY_EVENTS.forEach(function (evt) {
            document.addEventListener(evt, onActivity, { passive: true });
        });

        // Also listen for visibility changes (tab focus)
        document.addEventListener('visibilitychange', function () {
            if (!document.hidden) onActivity();
        });

        resetTimers();
    }

    // Start when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
