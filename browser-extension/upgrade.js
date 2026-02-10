// Get message from URL params
const params = new URLSearchParams(window.location.search);
const message = params.get('message');
if (message) {
    document.getElementById('message').textContent = message;
}

// Close button - try multiple methods
document.getElementById('closeBtn').addEventListener('click', () => {
    // Try to go back first
    if (window.history.length > 1) {
        window.history.back();
    } else {
        // Try to close (works if opened by script)
        window.close();
        // If still here, redirect to a safe page
        setTimeout(() => {
            window.location.href = 'https://securelinkapp.com';
        }, 100);
    }
});
