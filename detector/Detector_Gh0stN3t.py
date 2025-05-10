#!/usr/bin/env python3
"""
Home AP Guardian - Focused Wireless Intrusion Detection System
Monitors a specific BSSID for all known attack vectors
"""
from scapy.all import *
from collections import defaultdict, deque
import time
import subprocess
import sys
from logging import FileHandler, StreamHandler, Formatter, Filter
from datetime import datetime
import threading
import statistics  # Added for mean calculation
import json
import os



# ===== LOGGING SETUP =====
os.makedirs('logs', exist_ok=True)

class InfoFilter(logging.Filter):
    def filter(self, record):
        return record.levelno == logging.INFO

class AlertFilter(logging.Filter):
    def filter(self, record):
        return record.levelno >= logging.WARNING  # WARNING and above

                
# Clear any existing handlers
root_logger = logging.getLogger()
root_logger.handlers.clear()

# Info handler (only INFO level)
info_handler = FileHandler('/home/kali/Desktop/project_active/detector/logs/info.log')
info_handler.setLevel(logging.INFO)
info_handler.addFilter(InfoFilter())
info_handler.setFormatter(Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Alert handler (WARNING and above)
alert_handler = FileHandler('/home/kali/Desktop/project_active/detector/logs/alerts.log')
alert_handler.setLevel(logging.WARNING)
alert_handler.addFilter(AlertFilter())
alert_handler.setFormatter(Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Console handler (all levels)
console_handler = StreamHandler()
console_handler.setFormatter(Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Configure root logger
root_logger.setLevel(logging.INFO)
root_logger.addHandler(info_handler)
root_logger.addHandler(alert_handler)
root_logger.addHandler(console_handler)
# ===== END LOGGING SETUP =====

# ===== CONFIGURATION =====
YOUR_AP_BSSID = "40:AE:30:2B:E8:0E"  # CHANGE TO YOUR AP's REAL BSSID
AP_SSID = "TP-Link_E80E"
YOUR_AP_CHANNEL =  3         # Your AP's channel
INTERFACE = "wlan0mon"        # Your monitor interface
CLIENTS_LOG_PATH = "/home/kali/Desktop/project_active/detector/logs/active_clients.log"
# =========================

# Detection thresholds
DEAUTH_THRESHOLD = 5                 # Alerts after X deauths
PROBE_THRESHOLD = 10                 # Suspicious probe count
CLIENT_FLOOD_THRESHOLD = 20          # New clients/min
RSSI_ANOMALY_THRESHOLD = 15          # dBm change from baseline
BURST_THRESHOLD = 0.1                # Seconds between packets to consider a burst

# Attack signatures
COMMON_ATTACK_SSIDS = {
    "Free WiFi", "Starbucks", "Airport_WiFi", "Hotel_Guest",
    "attwifi", "xfinitywifi", "Google Starbucks", "Facebook WiFi"
}

# Global variables
deauth_counts = defaultdict(int)
packet_timestamps = defaultdict(deque)


### HELPER FUNCTIONS FOR DEAuth
def reset_counts():
    """Reset counters every 5 seconds"""
    global deauth_counts
    deauth_counts.clear()
    print("[+] Reset deauth counters")
    threading.Timer(5.0, reset_counts).start()

def mean(data):
    """Calculate mean of a list"""
    return statistics.mean(data) if data else 0

def is_burst(src_mac):
    """Check if packets arrive too fast (burst detection)"""
    global packet_timestamps
    timestamps = packet_timestamps[src_mac]
    if len(timestamps) < 2:
        return False, 0
    deltas = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    mean_delta = mean(deltas)
    return mean_delta < BURST_THRESHOLD, mean_delta
#################################################

class APGuardian:
    def __init__(self):
        self.known_clients = set()
        self.suspicious_activity = defaultdict(int)
        self.client_rssi_baseline = {}
        self.last_channel_check = time.time()
        self.packet_timestamps = defaultdict(deque)
        self.ap_ssid = AP_SSID
        self.ap_bssid = YOUR_AP_BSSID
        self.ap_mac = YOUR_AP_BSSID
        
        # Updated client data structure with status field
        self.connected_clients = []
        
        # Attack detectors
        self.fingerprint_learned = False
        self.real_fingerprint = {}
        self.deauth_counter = defaultdict(int)
        self.probe_counter = defaultdict(int)
        self.client_flood_detector = deque(maxlen=60)
        
        # Last time clients were saved to file
        self.last_clients_save = time.time()
        
        # Ensure we're on the right channel
        self.set_monitor_channel()


    def set_monitor_channel(self):
        # channel setting with interface verification
        max_retries = 3
        for attempt in range(max_retries):
            try:
                subprocess.run(
                    f"sudo iw dev {INTERFACE} set channel {YOUR_AP_CHANNEL}".split(),
                    check=True,
                    stderr=subprocess.PIPE
                )
                logging.info(f"Interface {INTERFACE} reset to channel {YOUR_AP_CHANNEL}")
                return
            except subprocess.CalledProcessError as e:
                logging.error(f"Channel set failed (attempt {attempt+1}/{max_retries}): {e.stderr.decode()}")
                time.sleep(2)
        logging.error("Failed to set channel after multiple attempts!")

    def learn_ap_fingerprint(self, pkt):
        """Learn fingerprint of the real AP for later detection."""
        if not pkt.haslayer(Dot11Beacon):
            return

        bssid = pkt.addr2
        elt = pkt.getlayer(Dot11Elt)

        try:
            ssid = elt.info.decode('utf-8', errors='ignore').strip()
        except Exception:
            return

        if bssid.lower() == YOUR_AP_BSSID.lower() and ssid == AP_SSID:
            try:
                interval = pkt[Dot11Beacon].beacon_interval
                cap = pkt.sprintf("{Dot11Beacon: %Dot11Beacon.cap%}")

                # Traverse Dot11Elt layers to find the one with ID == 3 (supported rates)
                rates = b""
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 3:
                        rates = elt.info
                        break
                    elt = elt.payload

                self.real_fingerprint = {
                    "interval": interval,
                    "capabilities": cap,
                    "rates": rates
                }

                self.fingerprint_learned = True
                logging.info(f"📡 Learned fingerprint for {ssid} ({bssid})")
                logging.info(f"➡ Interval: {interval} | Capabilities: {cap} | Rates: {rates.hex()}")
            except Exception as e:
                logging.error(f"Failed to learn fingerprint: {e}")

    def detect_rogue_ap(self, pkt):
        """Detect Evil Twin APs mimicking the real AP but with mismatched fingerprint."""
        if not pkt.haslayer(Dot11Beacon):
            return

        bssid = pkt.addr2
        elt = pkt.getlayer(Dot11Elt)

        try:
            ssid = elt.info.decode('utf-8', errors='ignore').strip()
        except Exception:
            return

        # Ignore unrelated SSIDs
        if ssid != self.ap_ssid:
            return

        # Skip the legit AP itself
        if bssid.lower() == self.ap_mac.lower():
            return

        # Skip if we haven't learned the real fingerprint yet
        if not self.fingerprint_learned:
            return

        # Extract fingerprint from current beacon
        try:
            interval = pkt[Dot11Beacon].beacon_interval
            cap = pkt.sprintf("{Dot11Beacon: %Dot11Beacon.cap%}")

            # Traverse Dot11Elt to get Supported Rates (ID=1) and Channel (ID=3 or ID=7)
            rates = b""
            channel = None
            current = elt

            while isinstance(current, Dot11Elt):
                if current.ID == 3:  # DS Parameter Set (Channel)
                    try:
                        channel = ord(current.info)
                    except:
                        channel = None
                elif current.ID == 7:  # Country Info or HT Operation (channel might be here too)
                    pass
                elif current.ID == 1:  # Supported rates
                    rates = current.info
                current = current.payload

        except Exception as e:
            logging.error(f"[!] Error extracting beacon fingerprint: {e}")
            return

        mismatch = []
        print(f"{ssid}, {interval}, {cap}, {rates}")
        real_fp = self.real_fingerprint
        if ssid != self.ap_ssid:
            mismatch.append("SSID")
        if bssid.lower() == self.ap_mac.lower():
            mismatch.append("BSSID (should not match legit)")
        if interval != real_fp.get("interval"):
            mismatch.append("interval")
        if cap != real_fp.get("capabilities"):
            mismatch.append("capabilities")
        if rates != real_fp.get("rates"):
            mismatch.append("rates")
        if channel and real_fp.get("channel") and channel != real_fp.get("channel"):
            mismatch.append("channel")
        if mismatch:
            logging.critical(f"EVIL TWIN DETECTED | BSSID: {bssid} | SSID: {ssid} | Mismatches: {', '.join(mismatch)}")


    def detect_deauth_attack(self, pkt):
        """Enhanced deauth detection combining both approaches"""
        if not pkt.haslayer(Dot11Deauth):
            return

        dot11 = pkt[Dot11]
        radio = pkt[RadioTap] if pkt.haslayer(RadioTap) else None

        claimed_src = dot11.addr2.lower() if dot11.addr2 else "unknown"
        dst_mac = dot11.addr1.lower() if dot11.addr1 else "unknown"
        reason = pkt[Dot11Deauth].reason

        rssi = getattr(radio, 'dBm_AntSignal', None)
        # Attacker MAC detection
        attacker_mac = "unknown"
        if radio and hasattr(radio, 'addr2'):
            ta_mac = radio.addr2.lower()
        if ta_mac != claimed_src:
            attacker_mac = ta_mac
        # Rule 1: Ignore common non-malicious reason codes
        if reason in [1, 3, 4, 6]:  # 1=Unspecified, 3=STA leaving, 4=Inactivity
            logging.debug(f"Ignoring normal deauth (code {reason}) from {claimed_src}")
            return

        # Update tracking metrics
        now = time.time()
        self.packet_timestamps[claimed_src].append(now)
        self.deauth_counter[claimed_src] += 1

        # Rule 2: Burst detection
        burst_detected, mean_delta = is_burst(claimed_src)
        if burst_detected:
            logging.warning(
                f"Deauth burst from {claimed_src} (avg interval: {mean_delta:.3f}s, "
                f"count: {self.deauth_counter[claimed_src]})"
            )

        # Rule 3: Threshold detection
        if self.deauth_counter[claimed_src] == DEAUTH_THRESHOLD:
            logging.critical(
                f"DEAUTH ATTACK DETECTED!\n"
                f"  Claimed source: {claimed_src}\n"
                f"  Attacker mac: {attacker_mac}\n"
                f"  Target: {dst_mac}"
            )

    def find_client_by_mac(self, mac):
        """Helper method to find a client by MAC address in the new data structure"""
        for client in self.connected_clients:
            if client['mac'] == mac:
                return client
        return None

    def monitor_clients(self, pkt):
        """
        Enhanced monitor_clients method that accurately tracks client connections
        by analyzing authentication state and specific frame types.
        """
        if not pkt.haslayer(Dot11):
            return
            
        # Basic validation
        if not hasattr(pkt, 'addr1') or not hasattr(pkt, 'addr2'):
            return
            
        src = pkt.addr2
        dst = pkt.addr1
        
        # Ensure src and dst are valid before using .lower()
        if not src or not dst:
            return
            
        # Only track frames involving our AP
        if self.ap_mac.lower() not in [src.lower(), dst.lower()]:
            return
            
        # Get RSSI if available
        rssi = None
        if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal'):
            rssi = pkt[RadioTap].dBm_AntSignal
            rssi_str = f"{rssi} dBm" if rssi is not None else "N/A"
        else:
            rssi_str = "N/A"
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # CASE 1: Track Authentication and Association
        if pkt.haslayer(Dot11Auth):
            if dst.lower() == self.ap_mac.lower():  # Client -> AP
                client_mac = src.lower()
                if pkt[Dot11Auth].status == 0:  # Successful authentication
                    self._update_client_state(client_mac, current_time, rssi_str, "Authenticated", "AUTH")
        
        elif pkt.haslayer(Dot11AssoResp):
            if src.lower() == self.ap_mac.lower():  # AP -> Client
                client_mac = dst.lower()
                if pkt[Dot11AssoResp].status == 0:  # Successful association
                    self._update_client_state(client_mac, current_time, rssi_str, "Associated", "ASSOC")
        
        # CASE 2: Data frames confirm an established connection
        elif pkt.type == 2:  # Data frame
            # Skip management frames (type 0) and control frames (type 1)
            # Only consider data frames from/to AP that have a non-empty payload
            if pkt.haslayer(Dot11) and pkt.type == 2 and Raw in pkt and len(pkt[Raw].load) > 0:
                if src.lower() == self.ap_mac.lower():
                    client_mac = dst.lower()
                elif dst.lower() == self.ap_mac.lower():
                    client_mac = src.lower()
                else:
                    return  # Not AP related
                    
                # Skip if it's AP-to-AP communication
                if client_mac == self.ap_mac.lower():
                    return
                    
                # If we see actual data flowing, client is definitely connected
                self._update_client_state(client_mac, current_time, rssi_str, "Connected", "DATA")
                
        # CASE 3: Detect disconnection
        elif pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            frame_type = "DEAUTH" if pkt.haslayer(Dot11Deauth) else "DISASSOC"
            
            # Handle AP->Client disconnection
            if src.lower() == self.ap_mac.lower():
                client_mac = dst.lower()
            # Handle Client->AP disconnection  
            elif dst.lower() == self.ap_mac.lower():
                client_mac = src.lower()
            else:
                return  # Not AP related
                
            # Skip AP-to-AP communication
            if client_mac == self.ap_mac.lower():
                return
                
            existing_client = self.find_client_by_mac(client_mac)
            if existing_client:
                existing_client['status'] = "Disconnected"
                existing_client['last_seen'] = current_time
                self._log_client_event(client_mac, "DISCONNECTED", rssi_str, src, dst, frame_type)
                
                # Remove the disconnected client from the active clients list
                self.remove_client_from_list(client_mac)

                
        # CASE 4: Maintain connection state based on periodic messages
        # Null frames, QoS Null frames, and other control frames that show connection maintenance
        elif pkt.type == 1:  # Control frame
            # Subtype 12 = QoS Null; subtype 4 = Null function (non-QoS)
            if pkt.subtype in [4, 12]:  # Null or QoS Null function frame
                if src.lower() == self.ap_mac.lower():
                    client_mac = dst.lower()
                elif dst.lower() == self.ap_mac.lower():
                    client_mac = src.lower()
                else:
                    return

                # Skip AP-to-AP communication
                if client_mac == self.ap_mac.lower():
                    return

                # Update last_seen but don't change status
                existing_client = self.find_client_by_mac(client_mac)
                if existing_client and existing_client['status'] == "Connected":
                    existing_client['last_seen'] = current_time
                    if rssi is not None:
                        existing_client['rssi'] = rssi_str
    
    def remove_client_from_list(self, client_mac):
        """
        Remove a client from the list of active clients based on the MAC address.
        """
        self.connected_clients = [client for client in self.connected_clients if client['mac'] != client_mac]


    def _update_client_state(self, client_mac, current_time, rssi_str, status, frame_type):
        """
        Helper method to update client state based on observed frames
        """
        existing_client = self.find_client_by_mac(client_mac)
        
        if not existing_client:
            # Add new client
            new_client = {
                'mac': client_mac,
                'first_seen': current_time,
                'last_seen': current_time,
                'rssi': rssi_str,
                'status': status
            }
            self.connected_clients.append(new_client)
            self._log_client_event(client_mac, f"NEW {status}", rssi_str, "", "", frame_type)
        else:
            # Update existing client
            existing_client['last_seen'] = current_time
            if rssi_str != "N/A":
                existing_client['rssi'] = rssi_str
                
            # Only upgrade status (Authenticated -> Associated -> Connected)
            status_hierarchy = {
                "Disconnected": 0,
                "Authenticated": 1,
                "Associated": 2,
                "Connected": 3
            }
            
            current_status = existing_client['status']
            if status_hierarchy.get(status, 0) > status_hierarchy.get(current_status, 0):
                existing_client['status'] = status
                self._log_client_event(client_mac, f"STATUS CHANGE: {current_status} -> {status}", 
                                    rssi_str, "", "", frame_type)
                                    
    def _log_client_event(self, mac, event, rssi_str, src, dst, frame_type):
        """Log client events to info.log and console"""
        # This will appear in info.log and console only
        logging.info(
            f"CLIENT {event.upper()} | "
            f"MAC: {mac} | "
            f"RSSI: {rssi_str} | "
            f"Frame: {frame_type} | "
            f"Path: {src} → {dst}"
        )
        
    def save_clients_to_file(self):
        """Save the current state of connected clients to a file"""
        try:
            # Format is already the list of dictionaries as requested
            json_data = json.dumps(self.connected_clients, indent=2)
            
            # Write to file
            with open(CLIENTS_LOG_PATH, 'w') as f:
                f.write(json_data)
                
            logging.debug(f"Saved {len(self.connected_clients)} clients to {CLIENTS_LOG_PATH}")
        except Exception as e:
            logging.error(f"Failed to save clients to file: {str(e)}")

    def packet_handler(self, pkt):
        """Main packet processing function"""
        try:
            if not self.fingerprint_learned:
                self.learn_ap_fingerprint(pkt)
            # Verify channel every 5 minutes
            if time.time() - self.last_channel_check > 300:
                self.set_monitor_channel()
                self.last_channel_check = time.time()
                
            # Check if it's time to save client data (every second)
            current_time = time.time()
            if current_time - self.last_clients_save >= 1.0:
                self.save_clients_to_file()
                self.last_clients_save = current_time

            # Run all detectors
            self.detect_rogue_ap(pkt)
            self.detect_deauth_attack(pkt)
            self.monitor_clients(pkt)
            #self.detect_probe_attacks(pkt)
            #self.detect_injection_attempts(pkt)

        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")


def enable_monitor_mode(interface):
    """Enables monitor mode on the specified wireless interface."""
    try:
        subprocess.run(["sudo", "ifconfig", interface, "down"], check=True)
        subprocess.run(["sudo","iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["sudo", "ifconfig", interface, "up"], check=True)
        logging.info(f"Interface {interface} set to monitor mode successfully.")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"[!] Failed to set {interface} to monitor mode: {e}")
        return False

def verify_interface():
    try:
        # 1 Check interface existence
        iwconfig_output = subprocess.check_output(
            ["iwconfig", INTERFACE],
            stderr=subprocess.STDOUT
        ).decode()

        # 2 Verify monitor mode
        if "Mode:Monitor" not in iwconfig_output:
            if not enable_monitor_mode(INTERFACE):
                logging.error("Interface not in monitor mode!")
                return False

        # 3 Check channel
        channel_info = subprocess.check_output(
            ["iw", "dev", INTERFACE, "info"],
            stderr=subprocess.STDOUT
        ).decode()
        
        if f"channel {YOUR_AP_CHANNEL}" not in channel_info:
            logging.warning(f"Not on channel {YOUR_AP_CHANNEL}! Detection may fail")

        return True

    except subprocess.CalledProcessError as e:
        error_msg = e.output.decode().strip()
        if "No such device" in error_msg:
            logging.error(f"Interface {INTERFACE} does not exist!")
        elif "Device or resource busy" in error_msg:
            logging.error(f"Interface {INTERFACE} is not available!")
        else:
            logging.error(f"Interface verification failed: {error_msg}")
        return False
        
    except Exception as e:
        logging.error(f"Unexpected verification error: {str(e)}")
        return False

def packet_handler_wrapper(guardian):
    """Wrapper function with error handling for packet sniffing"""
    while True:
        try:
            sniff(
                iface=INTERFACE,
                prn=guardian.packet_handler,
                store=False,
                timeout=10  # Check interface status periodically
            )
        except Exception as e:
            logging.error(f"Packet capture error: {str(e)}")
            if "Network is down" in str(e):
                logging.critical("Network interface down! Attempting recovery...")
                guardian.set_monitor_channel()  # Reinitialize interface
                time.sleep(5)  # Wait before retrying
            else:
                logging.error("Unknown capture error, restarting sniff...")
                time.sleep(1)


def main():
    logging.info(f"Starting AP Guardian for BSSID: {YOUR_AP_BSSID}")
    
    if not verify_interface():
        logging.warning("Running with reduced capabilities")
    
    guardian = APGuardian()
    
    try:
        logging.info("Beginning focused monitoring...")
        # Start packet sniffing in a daemon thread
        sniff_thread = threading.Thread(
            target=packet_handler_wrapper,
            args=(guardian,),
            daemon=True
        )
        sniff_thread.start()
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logging.info("Stopping AP Guardian")
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()