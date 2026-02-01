// RegWatch Dashboard JavaScript
// Handles dynamic interactions and API calls

// Configuration
const API_BASE = '/api';
let currentRegulation = 'hipaa';
let currentPermissionMode = 'request_approval';

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
    loadDashboardData();
});

function initializeDashboard() {
    // Load saved preferences from localStorage
    const savedRegulation = localStorage.getItem('regulation');
    const savedPermissionMode = localStorage.getItem('permissionMode');

    if (savedRegulation) {
        currentRegulation = savedRegulation;
        const selector = document.getElementById('regulation-selector');
        if (selector) selector.value = savedRegulation;
    }

    if (savedPermissionMode) {
        currentPermissionMode = savedPermissionMode;
        const selector = document.getElementById('permission-mode');
        if (selector) selector.value = savedPermissionMode;
    }
}

// Regulation Switcher
function switchRegulation() {
    const selector = document.getElementById('regulation-selector');
    const newRegulation = selector.value;

    if (newRegulation !== 'hipaa') {
        alert('Only HIPAA is currently supported. GDPR, SOX, and PCI-DSS are coming soon!');
        selector.value = currentRegulation;
        return;
    }

    currentRegulation = newRegulation;
    localStorage.setItem('regulation', newRegulation);

    // Reload dashboard with new regulation
    showNotification(`Switched to ${newRegulation.toUpperCase()} compliance checks`, 'success');
    loadDashboardData();
}

// Permission Mode Updater
function updatePermissionMode() {
    const selector = document.getElementById('permission-mode');
    const newMode = selector.value;

    currentPermissionMode = newMode;
    localStorage.setItem('permissionMode', newMode);

    let message = '';
    switch(newMode) {
        case 'auto_apply':
            message = '⚠️ Auto-Apply mode enabled. RegWatch will automatically merge approved fixes.';
            break;
        case 'request_approval':
            message = '✅ Request Approval mode enabled. RegWatch will create PRs for your review.';
            break;
        case 'notify_only':
            message = 'ℹ️ Notify Only mode enabled. RegWatch will alert but not make changes.';
            break;
    }

    showNotification(message, 'info');

    // Update backend
    updateBackendPermissionMode(newMode);
}

async function updateBackendPermissionMode(mode) {
    try {
        const response = await fetch(`${API_BASE}/settings/permission-mode`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode: mode })
        });

        if (!response.ok) {
            console.error('Failed to update permission mode');
        }
    } catch (error) {
        console.error('Error updating permission mode:', error);
    }
}

// Load Dashboard Data
async function loadDashboardData() {
    try {
        // Load compliance score
        const statsResponse = await fetch(`${API_BASE}/stats`);
        if (statsResponse.ok) {
            const stats = await statsResponse.json();
            updateDashboardStats(stats);
        }

        // Load activity feed
        const activityResponse = await fetch(`${API_BASE}/activity`);
        if (activityResponse.ok) {
            const activity = await activityResponse.json();
            // Activity feed is static in HTML for demo, but could be dynamic
        }

        // Load issues
        const issuesResponse = await fetch(`${API_BASE}/issues`);
        if (issuesResponse.ok) {
            const issues = await issuesResponse.json();
            // Issues are static in HTML for demo, but could be dynamic
        }

    } catch (error) {
        console.error('Error loading dashboard data:', error);
    }
}

function updateDashboardStats(stats) {
    // Update stat cards if they exist
    const elements = {
        'compliance-score': stats.compliance_score || '--',
        'active-issues': stats.active_issues || '--',
        'fine-exposure': stats.fine_exposure ? `$${stats.fine_exposure.toLocaleString()}` : '$--',
        'fixed-issues': stats.fixed_issues_24h || '--'
    };

    for (const [id, value] of Object.entries(elements)) {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    }
}

// Activity Feed Filtering
function filterActivity(type) {
    const items = document.querySelectorAll('.activity-item');
    const buttons = document.querySelectorAll('.activity-filter .filter-btn');

    // Update active button
    buttons.forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    // Filter items
    items.forEach(item => {
        if (type === 'all' || item.getAttribute('data-agent') === type) {
            item.style.display = 'flex';
        } else {
            item.style.display = 'none';
        }
    });
}

// Issues Filtering
function filterIssues(type) {
    const items = document.querySelectorAll('.issue-item');
    const buttons = document.querySelectorAll('.issues-filter .filter-btn');

    // Update active button
    buttons.forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    // Filter items
    items.forEach(item => {
        const itemType = item.getAttribute('data-type');
        if (type === 'all' || itemType === type) {
            item.style.display = 'block';
        } else {
            item.style.display = 'none';
        }
    });
}

// View Pull Request Diff
async function viewDiff(prNumber) {
    try {
        const response = await fetch(`${API_BASE}/pr/${prNumber}/diff`);
        if (response.ok) {
            const diff = await response.json();
            showDiffModal(diff);
        } else {
            // Fallback to GitHub
            window.open(`https://github.com/abhinavballa/RegWatch/pull/${prNumber}/files`, '_blank');
        }
    } catch (error) {
        console.error('Error fetching diff:', error);
        window.open(`https://github.com/abhinavballa/RegWatch/pull/${prNumber}/files`, '_blank');
    }
}

// View Git Issue Guidance
async function viewGuidance(issueNumber) {
    window.open(`https://github.com/abhinavballa/RegWatch/issues/${issueNumber}`, '_blank');
}

// View Regulation Change
function viewRegulationChange() {
    // Show modal with regulation change details
    alert('Regulation change details viewer coming soon!');
}

// Show Diff Modal (could be enhanced with a proper modal)
function showDiffModal(diff) {
    alert('Diff viewer coming soon!\n\n' + JSON.stringify(diff, null, 2));
}

// Notifications
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background-color: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#3b82f6'};
        color: white;
        border-radius: 0.5rem;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        z-index: 1000;
        max-width: 400px;
        animation: slideIn 0.3s ease-out;
    `;

    document.body.appendChild(notification);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// Add CSS animations for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Utility Functions
function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;

    return date.toLocaleDateString();
}

function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD',
        minimumFractionDigits: 0,
        maximumFractionDigits: 0
    }).format(amount);
}

// Simulate Regulation Change (for demo purposes)
async function simulateRegulationChange() {
    const regulationData = {
        regulation_id: 'HIPAA § 164.312(a)(2)(iv)',
        full_text: 'Implement a mechanism to encrypt electronic protected health information (ePHI) using AES-256-GCM or stronger encryption algorithm. All cryptographic modules must be FIPS 140-2 Level 2 certified or higher.'
    };

    try {
        showNotification('Simulating regulation change...', 'info');

        const response = await fetch(`${API_BASE}/simulate-regulation-change`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(regulationData)
        });

        if (response.ok) {
            const result = await response.json();
            showNotification('Regulation change simulation complete!', 'success');
            console.log('Simulation result:', result);

            // Reload dashboard to show new activity
            setTimeout(() => loadDashboardData(), 1000);
        } else {
            showNotification('Simulation failed', 'error');
        }
    } catch (error) {
        console.error('Simulation error:', error);
        showNotification('Simulation error: ' + error.message, 'error');
    }
}

// Export functions for use in HTML
window.switchRegulation = switchRegulation;
window.updatePermissionMode = updatePermissionMode;
window.filterActivity = filterActivity;
window.filterIssues = filterIssues;
window.viewDiff = viewDiff;
window.viewGuidance = viewGuidance;
window.viewRegulationChange = viewRegulationChange;
window.simulateRegulationChange = simulateRegulationChange;
