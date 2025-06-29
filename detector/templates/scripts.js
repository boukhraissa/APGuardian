// Global variables
let currentFilter = 'all';
let alertsData = [];
let infoData = [];

// Update timestamp
function updateTimestamp() {
    const now = new Date();
    document.getElementById('timestamp').textContent = now.toTimeString().substring(0, 8);
}
setInterval(updateTimestamp, 1000);
updateTimestamp();

function handlePcapDownload(event, filename) {
    // Prevent the default anchor behavior
    event.preventDefault();
    
    // Show loading state on the button
    const btn = event.target;
    const originalText = btn.textContent;
    btn.textContent = "Downloading...";
    btn.disabled = true;
    
    // First check if the file exists
    fetch(`/api/pcap/list`)
        .then(response => response.json())
        .then(data => {
            if (data.files && data.files.includes(filename)) {
                // File exists, proceed with download
                window.location.href = `/api/pcap/download/${filename}`;
                setTimeout(() => {
                    // Reset button after a delay
                    btn.textContent = originalText;
                    btn.disabled = false;
                }, 2000);
            } else {
                // File doesn't exist
                displayError(`PCAP file ${filename} not found. It may take up to 10 seconds after an attack to generate.`);
                btn.textContent = "Not Available";
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.disabled = false;
                }, 3000);
            }
        })
        .catch(error => {
            console.error('Error checking PCAP file:', error);
            displayError('Could not verify PCAP file availability');
            btn.textContent = originalText;
            btn.disabled = false;
        });
}

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
        const response = await fetch('/api/connections/active');
        const connections = await response.json();
        const table = document.getElementById('user-connections');
        const tbody = table.querySelector('tbody');
        tbody.innerHTML = '';
        
        if (connections.length === 0) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 4;  // Adjusted for 4 columns
            cell.textContent = 'No connections found';
            row.appendChild(cell);
            tbody.appendChild(row);
        } else {
            connections.forEach(conn => {
                const row = document.createElement('tr');
                
                // Comprehensive status determination
                let statusLabel = "Unknown";
                let statusClass = "status-unknown";
                
                if (conn.status === "Disconnected") {
                    statusLabel = "Disconnected";
                    statusClass = "status-disconnected";
                } else if (conn.is_new) {
                    statusLabel = "New Device";
                    statusClass = "status-new";
                } else if (!conn.whitelisted) {
                    statusLabel = "Suspicious";
                    statusClass = "status-suspicious";
                } else if (conn.whitelisted) {
                    statusLabel = "Trusted";
                    statusClass = "status-safe";
                }
                
                // Determine first seen with intelligent formatting
                const firstSeenDisplay = conn.first_seen === "N/A"
                    ? "Unknown"
                    : new Date(conn.first_seen).toLocaleString();
                
                // Ensure RSSI is displayed correctly
                const signalStrength = typeof conn.rssi === 'number'
                    ? `${conn.rssi} dBm`
                    : conn.rssi;
                
                // Create cells for each piece of data
                row.innerHTML = `
                    <td>${firstSeenDisplay}</td>
                    <td>${conn.mac}</td>
                    <td>${signalStrength}</td>
                    <td class="${statusClass}">${statusLabel}</td>
                `;
                
                tbody.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Error loading user connections:', error);
        
        // Add an error row to the table
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = 4;  // Adjusted for 4 columns
        cell.textContent = `Error loading connections: ${error.message}`;
        cell.classList.add('error-message');
        row.appendChild(cell);
        tbody.appendChild(row);
    }
}

// Load security alerts from alerts API
async function loadSecurityAlerts(filter = 'all') {
    try {
        // Update current filter if it's a user selection (not a refresh)
        if (filter !== 'refresh') {
            currentFilter = filter;
        }
        
        // Only refetch if we don't have data or forced refresh
        if (!alertsData.length || filter === 'refresh') {
            const response = await fetch('/api/logs/alerts');
            alertsData = await response.json();
        }
        
        const container = document.getElementById('alert-container');
        container.innerHTML = '';
        
        // Filter alerts by type if needed
        let filteredAlerts = [...alertsData];
        if (currentFilter === 'deauth') {
            filteredAlerts = alertsData.filter(alert => 
                alert.message && alert.message.toLowerCase().includes('deauth'));
        } else if (currentFilter === 'evil-twin') {
            filteredAlerts = alertsData.filter(alert => 
                alert.message && alert.message.toLowerCase().includes('evil twin'));
        }
        
        // Get most recent 5 alerts
        const recentAlerts = filteredAlerts.slice(-5).reverse();
        
        if (recentAlerts.length === 0) {
            container.innerHTML = '<div class="alert-item">No alerts found</div>';
        } else {
            recentAlerts.forEach(alert => {
                // Determine alert type
                const isDeauth = alert.message && alert.message.toLowerCase().includes('deauth');
                const isEvilTwin = alert.message && alert.message.toLowerCase().includes('evil twin');
                
                // Create alert HTML
                const alertDiv = document.createElement('div');
                alertDiv.className = `alert-item ${alert.level === 'CRITICAL' ? 'critical' : 'warning'}`;
                
                // Set alert title based on type
                let alertTitle = 'Security Alert';
                let pcapFileName = '';
                
                if (isDeauth) {
                    alertTitle = 'Deauthentication Attack';
                    // Extract timestamp for filename
                    const timestampStr = alert.timestamp.replace(/[: -]/g, '_');
                    const datePart = timestampStr.split('_').slice(0, 3).join('');
                    const timePart = timestampStr.split('_').slice(3).join('');
                    pcapFileName = `deauth_${datePart}_${timePart}.pcap`;
                }
                
                if (isEvilTwin) {
                    alertTitle = 'Evil Twin Attack';
                    // Extract timestamp for filename
                    const timestampStr = alert.timestamp.replace(/[: -]/g, '_');
                    const datePart = timestampStr.split('_').slice(0, 3).join('');
                    const timePart = timestampStr.split('_').slice(3).join('');
                    pcapFileName = `evil_twin_${datePart}_${timePart}.pcap`;
                }
                
                alertDiv.innerHTML = `
                    <div class="alert-details">
                        <div class="alert-title">${alertTitle}</div>
                        <div class="alert-desc">${alert.message}</div>
                        <div class="alert-meta">
                            <span class="alert-time">${alert.timestamp}</span>
                            <span class="alert-severity ${alert.level === 'CRITICAL' ? 'critical' : 'warning'}">${alert.level}</span>
                            ${(isDeauth || isEvilTwin) ? 
                                `<button class="btn btn-small pcap-download" style="margin-left: 250px;" 
                                onclick="handlePcapDownload(event, '${pcapFileName}')">Download PCAP</button>` : ''}
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
        
        document.querySelector(`.filter-button[data-filter="${currentFilter}"]`)?.classList.add('active');
        
    } catch (error) {
        console.error('Error loading security alerts:', error);
        displayError('Failed to load security alerts');
    }
}

// Load network and attack statistics
async function loadNetworkInfo() {
    try {
        const response = await fetch('/api/attacks/stats');
        const stats = await response.json();
        
        // Update statistics
        document.getElementById('ap-count').textContent = stats.unique_sources ? stats.unique_sources.length : '0';
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
        displayError('Failed to load network information');
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
    loadSecurityAlerts('refresh'); // Will use the currentFilter variable internally
    loadNetworkInfo();
}

// Add event listeners
document.addEventListener('DOMContentLoaded', function() {
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
    
    // Initial data load
    refreshAllData();
    
    // Set up automatic refresh
    setInterval(refreshAllData, 1000); // Refresh every second
});