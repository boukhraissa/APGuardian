#!/usr/bin/env python3
"""
log_parser.py - Parses log files from Gh0stN3t detector for display in web interface
Place this file in /home/kali/Desktop/project/interface/ directory
"""

import os
import json
import time
import re
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Path to log files - determine dynamically based on script location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
LOG_DIR = os.path.join(PROJECT_DIR, "detector", "logs")
ALERTS_LOG = os.path.join(LOG_DIR, "alerts.log")
INFO_LOG = os.path.join(LOG_DIR, "info.log")

logger.info(f"Log directory: {LOG_DIR}")
logger.info(f"Alerts log: {ALERTS_LOG}")
logger.info(f"Info log: {INFO_LOG}")

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Cache to store recent log data
log_cache = {
    "alerts": [],
    "info": [],
    "last_alert_read": 0,
    "last_info_read": 0
}

# Tracking active connections
active_connections = {}

def parse_log_line(line: str) -> Dict:
    """Parse a single log line into a structured dictionary."""
    try:
        # Updated log format parsing for your specific format
        # Example: 2025-05-07 17:29:54,890 - INFO - [2025-05-07 17:29:54] DISCONNECTED - 56:78:63:23:53:63 | RSSI: N/A | Frame: DEAUTH | Src: 40:ae:30:2b:e8:0e | Dst: 56:78:63:23:53:63
        
        # First, split by first ' - ' to get timestamp and rest
        parts = line.strip().split(' - ', 1)
        if len(parts) < 2:
            return None
            
        timestamp = parts[0]
        
        # Get level and message
        remaining = parts[1].split(' - ', 1)
        if len(remaining) < 2:
            level = remaining[0]
            message = ""
        else:
            level = remaining[0]
            message = remaining[1]
        
        # Extract source and target MAC addresses if present
        source = None
        target = None
        
        # Look for MAC addresses in common formats
        mac_pattern = r'(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}'
        mac_addresses = re.findall(mac_pattern, message)
        
        if len(mac_addresses) >= 2:
            source = mac_addresses[0]
            target = mac_addresses[1]
        elif len(mac_addresses) == 1:
            source = mac_addresses[0]
            
        # Alternatively check for explicitly labeled Source/Dst
        src_match = re.search(r'Src: ([^ |]+)', message)
        dst_match = re.search(r'Dst: ([^ |]+)', message)
        
        if src_match:
            source = src_match.group(1)
        if dst_match:
            target = dst_match.group(1)
            
        # Determine attack type
        attack_type = None
        if "DEAUTH ATTACK" in message:
            attack_type = "Deauthentication Attack"
        elif "EVIL TWIN" in message:
            attack_type = "Evil Twin Attack"
        
        # For client connections
        event_type = None
        if "CONNECTED" in message:
            event_type = "CONNECTED"
        elif "DISCONNECTED" in message:
            event_type = "DISCONNECTED"
        
        # Simplify timestamp for display
        try:
            dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S,%f")
            timestamp_formatted = dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            timestamp_formatted = timestamp
        
        return {
            "timestamp": timestamp_formatted,
            "level": level,
            "message": message,
            "attack_type": attack_type,
            "event_type": event_type,
            "source": source,
            "target": target,
            "raw": line.strip()
        }
    except Exception as e:
        logger.error(f"Error parsing log line: {e}")
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": "ERROR",
            "message": f"Error parsing log: {str(e)}",
            "raw": line.strip()
        }

def get_alerts(max_entries: int = 50, force_refresh: bool = False) -> List[Dict]:
    """Get alert logs from the alerts.log file."""
    if force_refresh or not log_cache["alerts"]:
        refresh_log_cache("alerts")
    
    # Filter logs to only include actual alerts (WARNING or higher)
    alerts = [log for log in log_cache["alerts"] 
              if log.get("level") in ["WARNING", "CRITICAL", "ERROR"]]
    
    return alerts[:max_entries]

def get_info_logs(max_entries: int = 100, force_refresh: bool = False) -> List[Dict]:
    """Get info logs from the info.log file."""
    if force_refresh or not log_cache["info"]:
        refresh_log_cache("info")
    
    # Filter for connection events for better display
    info_logs = [log for log in log_cache["info"] 
                if log.get("event_type") == "CONNECTED" or 
                   log.get("event_type") == "DISCONNECTED" or
                   "CLIENT" in log.get("message", "")]
    
    return info_logs[:max_entries]

def get_active_connections():
    """Get active connections based on recent log entries."""
    connections = []
    seen_ips = set()

    # Use the info log instead of hardcoded path
    log_file = INFO_LOG 
    
    # Set time limit to only show recent connections
    time_limit = datetime.now() - timedelta(minutes=5)  # recent 5 mins
    
    # Make sure log file exists before trying to read it
    if not os.path.exists(log_file):
        logger.warning(f"Log file not found: {log_file}")
        open(log_file, 'a').close()  # Create empty file
        return connections

    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
            
        for line in reversed(lines):  # Start from most recent
            if "CONNECT" in line:
                # Try to extract timestamp and IP
                try:
                    # Example format: "[2025-05-08 15:12:03] CONNECTED: 192.168.1.5"
                    # Extract timestamp
                    timestamp_match = re.search(r'\[(.*?)\]', line)
                    if timestamp_match:
                        timestamp_str = timestamp_match.group(1)
                        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        
                        if timestamp < time_limit:
                            break  # Stop processing older entries
                        
                        # Try to extract IP
                        ip_match = re.search(r'(?:CONNECTED|DISCONNECTED)[:\s]+(\d+\.\d+\.\d+\.\d+|(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})', line)
                        if ip_match:
                            client = ip_match.group(1)
                            
                            # For CONNECTED events
                            if "CONNECTED" in line and client not in seen_ips:
                                seen_ips.add(client)
                                connections.append({
                                    "ip": client,
                                    "timestamp": timestamp_str,
                                    "status": "connected"
                                })
                            
                            # For DISCONNECTED events
                            elif "DISCONNECTED" in line and client in seen_ips:
                                seen_ips.remove(client)
                                # Optional: Can mark as disconnected if needed
                
                except Exception as e:
                    logger.error(f"Error parsing connection entry: {e}")
                    continue
    except Exception as e:
        logger.error(f"Error reading connection log: {e}")
        
    # If no connections found from logs, provide a sample for testing
    if not connections and os.environ.get('DEBUG'):
        connections = [
            {
                "ip": "00:11:22:33:44:55",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "connected"
            },
            {
                "ip": "192.168.1.5",
                "timestamp": (datetime.now() - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"),
                "status": "connected"
            }
        ]
        
    return connections

def refresh_log_cache(log_type: str = "all") -> None:
    """Update the log cache with latest log entries."""
    if log_type in ["all", "alerts"]:
        try:
            if os.path.exists(ALERTS_LOG):
                with open(ALERTS_LOG, "r") as f:
                    # Get file size to check if it's been modified
                    file_size = os.path.getsize(ALERTS_LOG)
                    
                    if file_size != log_cache["last_alert_read"] or not log_cache["alerts"]:
                        log_cache["last_alert_read"] = file_size
                        lines = f.readlines()
                        log_cache["alerts"] = [
                            parsed_line for line in lines
                            if (parsed_line := parse_log_line(line)) is not None
                        ]
                        logger.debug(f"Refreshed alerts cache with {len(log_cache['alerts'])} entries")
            else:
                logger.warning(f"Alerts log file not found at: {ALERTS_LOG}")
                # Create empty log file
                with open(ALERTS_LOG, "w") as f:
                    pass
                log_cache["alerts"] = []
        except Exception as e:
            logger.error(f"Error reading alerts log: {e}")
    
    if log_type in ["all", "info"]:
        try:
            if os.path.exists(INFO_LOG):
                with open(INFO_LOG, "r") as f:
                    # Get file size to check if it's been modified
                    file_size = os.path.getsize(INFO_LOG)
                    
                    if file_size != log_cache["last_info_read"] or not log_cache["info"]:
                        log_cache["last_info_read"] = file_size
                        lines = f.readlines()
                        log_cache["info"] = [
                            parsed_line for line in lines
                            if (parsed_line := parse_log_line(line)) is not None
                        ]
                        logger.debug(f"Refreshed info cache with {len(log_cache['info'])} entries")
            else:
                logger.warning(f"Info log file not found at: {INFO_LOG}")
                # Create empty log file
                with open(INFO_LOG, "w") as f:
                    pass
                log_cache["info"] = []
        except Exception as e:
            logger.error(f"Error reading info log: {e}")

def get_latest_attacks(max_entries: int = 10) -> List[Dict]:
    """Get the most recent attacks from the alert logs."""
    alerts = get_alerts(max_entries=100, force_refresh=True)
    attack_logs = [alert for alert in alerts if alert.get("attack_type")]
    return attack_logs[:max_entries]

def get_attack_stats() -> Dict:
    """Get statistics about detected attacks."""
    alerts = get_alerts(max_entries=1000, force_refresh=True)
    
    stats = {
        "total_attacks": 0,
        "deauth_attacks": 0,
        "evil_twin_attacks": 0,
        "unique_sources": set(),
        "unique_targets": set(),
        "recent_timestamps": []
    }
    
    for alert in alerts:
        if "DEAUTH ATTACK" in alert.get("message", ""):
            stats["total_attacks"] += 1
            stats["deauth_attacks"] += 1
            if alert.get("source"):
                stats["unique_sources"].add(alert.get("source"))
                
        elif "EVIL TWIN" in alert.get("message", ""):
            stats["total_attacks"] += 1
            stats["evil_twin_attacks"] += 1
            if alert.get("target"):
                stats["unique_targets"].add(alert.get("target"))
        
        if alert.get("timestamp"):
            stats["recent_timestamps"].append(alert.get("timestamp"))
    
    # Get active client connection info
    active_clients = get_active_connections()
    
    # Add client info to stats
    stats["connected_clients"] = len(active_clients)
    
    # Convert sets to lists for JSON serialization
    stats["unique_sources"] = list(stats["unique_sources"])
    stats["unique_targets"] = list(stats["unique_targets"])
    
    return stats

def get_log_summary() -> Dict:
    """Get a summary of all logs."""
    refresh_log_cache()
    
    return {
        "alerts_count": len(log_cache["alerts"]),
        "info_count": len(log_cache["info"]),
        "attack_stats": get_attack_stats(),
        "active_connections": len(get_active_connections()),
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def create_test_logs():
    """Create test log entries for development and testing."""
    logger.info("Creating test log entries")
    
    # Ensure log directory exists
    os.makedirs(os.path.dirname(ALERTS_LOG), exist_ok=True)
    
    # Generate some test alerts
    with open(ALERTS_LOG, "a") as f:
        # Deauth attack alert
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')} - CRITICAL - [2025-05-08 12:30:15] DEAUTH ATTACK DETECTED - Src: 00:11:22:33:44:55 | Dst: AA:BB:CC:DD:EE:FF | Frames: 50\n")
        # Evil twin alert
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')} - WARNING - [2025-05-08 12:35:22] EVIL TWIN DETECTED - SSID: 'Home_Network' | BSSID: 11:22:33:44:55:66 | Channel: 6\n")
    
    # Generate some test info logs
    with open(INFO_LOG, "a") as f:
        # Connection logs
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')} - INFO - [2025-05-08 12:20:10] CONNECTED - 192.168.1.5 | RSSI: -65 | Channel: 1\n")
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')} - INFO - [2025-05-08 12:25:30] CONNECTED - 00:1A:2B:3C:4D:5E | RSSI: -72 | Channel: 1\n")
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')} - INFO - [2025-05-08 12:40:05] DISCONNECTED - 192.168.1.5 | Reason: Timeout\n")
    
    logger.info("Test logs created successfully")

if __name__ == "__main__":
    # Test the log parser
    print("Log Parser Test")
    print("--------------")
    print(f"Alerts log path: {ALERTS_LOG}")
    print(f"Info log path: {INFO_LOG}")
    
    print("\nChecking if log files exist:")
    print(f"Alerts log exists: {os.path.exists(ALERTS_LOG)}")
    print(f"Info log exists: {os.path.exists(INFO_LOG)}")
    
    # Create test logs if they don't exist or are empty
    if not os.path.exists(ALERTS_LOG) or os.path.getsize(ALERTS_LOG) == 0 or \
       not os.path.exists(INFO_LOG) or os.path.getsize(INFO_LOG) == 0:
        print("\nCreating test logs...")
        create_test_logs()
    
    summary = get_log_summary()
    print(f"\nTotal alerts: {summary['alerts_count']}")
    print(f"Total info logs: {summary['info_count']}")
    print(f"Active connections: {summary['active_connections']}")
    
    latest = get_latest_attacks(5)
    print("\nLatest attacks:")
    for attack in latest:
        print(f"{attack['timestamp']} - {attack.get('attack_type', 'Unknown')} - {attack['message']}")
        
    # Display active connections
    active = get_active_connections()
    print("\nActive connections:")
    for conn in active:
        print(f"{conn.get('timestamp', 'Unknown')} - {conn.get('ip', 'Unknown')} - {conn.get('status', 'Unknown')}")