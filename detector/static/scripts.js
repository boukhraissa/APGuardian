// Updated JavaScript code for dashboard.html
// Find and replace the existing script section with this code

// Global variables
let alertsData = [];
let infoData = [];

// Update timestamp
function updateTimestamp() {
    const now = new Date();
    document.getElementById('timestamp').textContent = now.toTimeString().substring(0, 8);
}
setInterval(updateTimestamp, 1000);
updateTimestamp();

// Generate fingerprint visualization
function generateFingerprint() {
    const container = document.getElementById('fingerprint-visual');
    const size = 180;
    const dotSize = 4;
    const dotCount = 40;
    
    container.innerHTML = ''; // Clear container
    
    for (let i = 0; i < dotCount; i++) {
        const dot = document.createElement('div');
        dot.className = 'fingerprint-dot';
        dot.style.width = `${dotSize}px`;
        dot.style.height = `${dotSize}px`;
        
        // Use sine/cosine to position dots in a circular pattern
        const angle = (i / dotCount) * Math.PI * 2;
        const distance = Math.random() * (size / 2 - dotSize);
        const x = Math.cos(angle) * distance + (size / 2 - dotSize / 2);
        const y = Math.sin(angle) * distance + (size / 2 - dotSize / 2);
        
        dot.style.left = `${x}px`;
        dot.style.top = `${y}px`;
        
        // Random opacity and animation delay
        dot.style.opacity = 0.3 + Math.random() * 0.7;
        dot.style.animationDelay = `${Math.random() * 5}s`;
        
        container.appendChild(dot);
    }
    
    // Add connecting lines
    for (let i = 0; i < 10; i++) {
        const line = document.createElement('div');
        line.className = 'fingerprint-line';
        
        const angle = Math.random() * Math.PI * 2;
        const length = 30 + Math.random() * 50;
        const thickness = 1 + Math.random();
        
        line.style.width = `${length}px`;
        line.style.height = `${thickness}px`;
        
        const x = Math.cos(angle) * (Math.random() * size / 4) + (size / 2);
        const y = Math.sin(angle) * (Math.random() * size / 4) + (size / 2);
        
        line.style.left = `${x - length / 2}px`;
        line.style.top = `${y}px`;
        line.style.transform = `rotate(${angle}rad)`;
        line.style.opacity = 0.3 + Math.random() * 0.4;
        line.style.animationDelay = `${Math.random() * 5}s`;
        
        container.appendChild(line);
    }
}

// Load user connections from info logs API
async function loadUserConnections() {
    try {
        console.log("Loading user connections...");
        const response = await fetch('/api/logs/info');
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        const data = await response.json();
        console.log("Info logs data:", data);
        infoData = data; // Store data globally
        
        const table = document.getElementById('user-connections');
        const tbody = table.querySelector('tbody');
        tbody.innerHTML = '';
        
        // Filter for connection events
        const connections = data
            .filter(entry => 
                entry.message && 
                (entry.message.toLowerCase().includes('connect') || 
                 entry.message.toLowerCase().includes('client')))
            .slice(-10);
        
        if (connections.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = '<td colspan="4" style="text-align: center;">No connection logs found</td>';
            tbody.appendChild(row);
        } else {
            connections.forEach(conn => {
                // Extract status from message
                const isConnected = conn.message && conn.message.toLowerCase().includes('connected');
                const status = isConnected ? 
                    '<span class="status-safe">Connected</span>' : 
                    '<span class="status-warning">Disconnected</span>';
                
                // Extract MAC addresses
                const sourceMac = conn.source || 'Unknown';
                const destMac = conn.target || 'Unknown';
                
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${conn.timestamp || 'Unknown'}</td>
                    <td>${sourceMac}</td>
                    <td>${destMac}</td>
                    <td>${status}</td>
                `;
                tbody.appendChild(row);
            });
        }
        
        // Update client count in network stats
        document.getElementById('client-count').textContent = connections.length || '0';
    } catch (error) {
        console.error('Error loading user connections:', error);
        displayError('Failed to load user connections: ' + error.message);
    }
}

// Load security alerts from alerts API
async function loadSecurityAlerts(filter = 'all') {
    try {
        console.log("Loading security alerts with filter:", filter);
        // Only refetch if we don't have data or forced refresh
        if (!alertsData.length || filter === 'refresh') {
            const response = await fetch('/api/logs/alerts');
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            
            alertsData = await response.json();
            console.log("Alerts data:", alertsData);
            filter = 'all'; // Reset to all after refresh
        }
        
        const container = document.getElementById('alert-container');
        container.innerHTML = '';
        
        // Filter alerts by type if needed
        let filteredAlerts = [...alertsData];
        if (filter === 'deauth') {
            filteredAlerts = alertsData.filter(alert => 
                alert.message && alert.message.toLowerCase().includes('deauth'));
        } else if (filter === 'evil-twin') {
            filteredAlerts = alertsData.filter(alert => 
                alert.message && alert.message.toLowerCase().includes('evil twin'));
        }
        
        // Get most recent 5 alerts
        const recentAlerts = filteredAlerts.slice(-5);
        
        if (recentAlerts.length === 0) {
            container.innerHTML = '<div class="alert-item">No alerts found</div>';
        } else {
            recentAlerts.forEach(alert => {
                // Determine alert type
                const isDeauth = alert.message && alert.message.toLowerCase().includes('deauth');
                const isEvilTwin = alert.message && alert.message.toLowerCase().includes('evil twin');
                
                // Set severity based on level
                const severity = (alert.level === 'CRITICAL') ? 'critical' : 'warning';
                
                // Create alert HTML
                const alertDiv = document.createElement('div');
                alertDiv.className = `alert-item ${severity}`;
                
                // Set alert title based on type
                let alertTitle = 'Security Alert';
                if (isDeauth) alertTitle = 'Deauthentication Attack';
                if (isEvilTwin) alertTitle = 'Evil Twin Attack';
                
                alertDiv.innerHTML = `
                    <div class="alert-details">
                        <div class="alert-title">${alertTitle}</div>
                        <div class="alert-desc">${alert.message || 'No details available'}</div>
                        <div class="alert-meta">
                            <span class="alert-time">${alert.timestamp || 'Unknown time'}</span>
                            <span class="alert-severity ${severity}">${alert.level || 'WARNING'}</span>
                        </div>
                    </div>
                `;
                
                container.appendChild(alertDiv);
            });
        }
        
        // Update filter buttons
        document.querySelectorAll('.filter-button').forEach(btn => {
            btn.classList.remove('active');
        });
        
        document.querySelector(`.filter-button[data-filter="${filter === 'refresh' ? 'all' : filter}"]`)?.classList.add('active');
        
        // Update deauth and evil twin counts in stats
        updateAttackCounts(filteredAlerts);
    } catch (error) {
        console.error('Error loading security alerts:', error);
        displayError('Failed to load security alerts: ' + error.message);
    }
}

// Update attack counts in the stats section
function updateAttackCounts(alerts) {
    const deauthCount = alerts.filter(alert => 
        alert.message && alert.message.toLowerCase().includes('deauth')).length;
    
    const evilTwinCount = alerts.filter(alert => 
        alert.message && alert.message.toLowerCase().includes('evil twin')).length;
    
    document.getElementById('deauth-count').textContent = deauthCount;
    document.getElementById('evil-twin-count').textContent = evilTwinCount;
}

// Load network and attack statistics
async function loadNetworkInfo() {
    try {
        console.log("Loading network stats...");
        const response = await fetch('/api/attacks/stats');
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        const stats = await response.json();
        console.log("Network stats:", stats);
        
        // Update statistics
        document.getElementById('ap-count').textContent = 
            stats.unique_sources ? stats.unique_sources.length : '0';
        document.getElementById('deauth-count').textContent = stats.deauth_attacks || '0';
        document.getElementById('evil-twin-count').textContent = stats.evil_twin_attacks || '0';
        
        // Update last scan time
        const now = new Date();
        const timeStr = now.toTimeString().substring(0, 8);
        document.getElementById('last-scan-time').textContent = timeStr;
        document.getElementById('last-refresh').textContent = timeStr;
        
        // Regenerate fingerprint for visual feedback
        generateFingerprint();
    } catch (error) {
        console.error('Error loading network info:', error);
        displayError('Failed to load network information: ' + error.message);
    }
}

// Display error message
function displayError(message) {
    const errorEl = document.getElementById('error-alert');
    errorEl.textContent = message;
    errorEl.style.display = 'block';
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        errorEl.style.display = 'none';
    }, 5000);
}

// Helper function to refresh all data
function refreshAllData() {
    loadUserConnections();
    loadSecurityAlerts('refresh');
    loadNetworkInfo();
}
function updateConnections() {
    fetch('/api/connections/active')
        .then(response => response.json())
        .then(data => {
            const list = document.getElementById('connectionsList');
            list.innerHTML = ''; // Clear old entries

            data.forEach(conn => {
                const li = document.createElement('li');
                li.textContent = `${conn.ip} - connected at ${conn.timestamp}`;
                list.appendChild(li);
            });
        })
        .catch(error => {
            console.error('Error fetching active connections:', error);
        });
}

// Add event listeners
document.addEventListener('DOMContentLoaded', function() {
    console.log("DOM loaded, initializing dashboard...");
    
    // Generate initial fingerprint
    generateFingerprint();
    
    // Set up refresh button handlers
    document.getElementById('refresh-users').addEventListener('click', loadUserConnections);
    document.getElementById('refresh-alerts').addEventListener('click', () => loadSecurityAlerts('refresh'));
    document.getElementById('refresh-network').addEventListener('click', loadNetworkInfo);
    
    // Set up filter buttons
    document.querySelectorAll('.filter-button').forEach(button => {
        button.addEventListener('click', function() {
            const filter = this.getAttribute('data-filter');
            loadSecurityAlerts(filter);
        });
    });
    
    // Add test API call to check if backend is responding
    fetch('/test')
        .then(response => response.json())
        .then(data => {
            console.log("API test successful:", data);
        })
        .catch(err => {
            console.error("API test failed:", err);
            displayError("Cannot connect to the backend API. Make sure the server is running.");
        });
    
    // Initial data load
    refreshAllData();
    
    // Set up automatic refresh
    setInterval(refreshAllData, 30000); // Refresh every 30 seconds
});

setInterval(updateConnections, 5000);

// Optional: call it once immediately on page load
window.addEventListener('DOMContentLoaded', updateConnections);