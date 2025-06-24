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
import requests



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
YOUR_AP_CHANNEL =  4       # Your AP's channel
INTERFACE = "wlan0mon"        # Your monitor interface
CLIENTS_LOG_PATH = "/home/kali/Desktop/project_active/detector/logs/active_clients.log"
# =========================

# Detection thresholds
DEAUTH_THRESHOLD = 5                 # Alerts after X deauths
PROBE_THRESHOLD = 10                 # Suspicious probe count
CLIENT_FLOOD_THRESHOLD = 20          # New clients/min
RSSI_ANOMALY_THRESHOLD = 15          # dBm change from baseline
BURST_THRESHOLD = 0.1                # Seconds between packets to consider a burst

# APGuardian telegram bot config
BOT_TOKEN = '8197673232:AAHDLf5UvAJQ0zSyJJTanW_1B4uScXuxWIU'
CHAT_ID = '1688882252'

# Global variables
deauth_counts = defaultdict(int)
packet_timestamps = defaultdict(deque)


### HELPER FUNCTIONS FOR DEAuth

def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"  # Optional: use Markdown formatting
    }

    try:
        requests.post(url, data=data)
    except Exception as e:
        print(f"[!] Telegram send failed: {e}")

def send_telegram_file(file_path, caption="Captured packets"):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
    with open(file_path, "rb") as f:
        requests.post(url, data={"chat_id": CHAT_ID, "caption": caption}, files={"document": f})

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
        self.whitelist = set()
        
        # Attack detectors
        self.fingerprint_learned = False
        self.channel_updated = False
        self.real_fingerprint = {}
        self.deauth_counter = defaultdict(int)
        self.probe_counter = defaultdict(int)
        self.client_activity = deque()  # Holds last 2 minutes of MAC+RSSI observations
        self.attackers_address = set()  # Detected suspicious MACs via RSSI correlation
        self.client_flood_detector = deque(maxlen=60)
        self.evil_twin_detected = False
        self.evil_twin_start_time = None
        self.evil_twin_packets = []
        self.deauth_attack_active = False
        self.deauth_attack_start = None
        self.deauth_packets = []
        # Last time clients were saved to file
        self.last_clients_save = time.time()
        
        # Ensure we're on the right channel
        self.set_monitor_channel()


    def save_pcap(self, packets, attack_type):
        """Save captured packets to a PCAP file"""
        # Create pcaps directory if it doesn't exist
        pcap_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures")
        os.makedirs(pcap_dir, exist_ok=True)
        
        # Generate filename with timestampd
        timestamp = (datetime.now()-timedelta(seconds=10)).strftime("%Y%m%d_%H%M%S")
        filename = f"{attack_type}_{timestamp}.pcap"
        filepath = os.path.join(pcap_dir, filename)
        # Write packets to file
        try:
            wrpcap(filepath, packets)
            logging.info(f"Saved PCAP file: {filename}")
            send_telegram_file(file_path=filepath, caption = "Captured packets")
            return filename
        except Exception as e:
            logging.error(f"Failed to save PCAP file: {e}")
            return None

    def capture_attack_packets(self, duration=10, attack_type="unknown"):
        """Capture packets for a specified duration after attack detection"""
        import threading
        
        def _capture_packets():
            try:
                # Capture packets for the specified duration
                logging.info(f"Capturing {attack_type} attack traffic for {duration} seconds...")
                packets = sniff(iface=INTERFACE, timeout=duration)
                
                # Save to PCAP file
                if packets:
                    self.save_pcap(packets, attack_type)
                else:
                    logging.warning("No packets captured during attack")
            except Exception as e:
                logging.error(f"Error capturing attack packets: {e}")
        
        # Start capture in a separate thread
        capture_thread = threading.Thread(target=_capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        
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

    def update_ap_channel(self, pkt):
        # Extracts the channel from a beacon frame
        global YOUR_AP_CHANNEL

        if not pkt.haslayer(Dot11Beacon):
            return

        bssid = pkt.addr2
        elt = pkt.getlayer(Dot11Elt)

        try:
            ssid = elt.info.decode('utf-8', errors='ignore').strip()
        except Exception:
            return

        if bssid.lower() != YOUR_AP_BSSID.lower() or ssid != AP_SSID:
            return

        current = elt
        while isinstance(current, Dot11Elt):
            if current.ID == 3:  # DS Parameter Set
                try:
                    channel = ord(current.info)
                    YOUR_AP_CHANNEL = channel
                    logging.info(f"[+] AP channel updated: {channel}")
                    self.channel_updated = True
                    return
                except:
                    return
            current = current.payload

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
                vendor_tag = None
                channel = None

                # Traverse all Dot11Elt layers
                current = elt
                while isinstance(current, Dot11Elt):
                    if current.ID == 3:  # DS Parameter Set → Channel
                        try:
                            channel = ord(current.info)
                        except:
                            channel = None
                    elif current.ID == 221:  # Vendor Specific
                        vendor_tag = current.info.hex()
                    current = current.payload

                self.real_fingerprint = {
                    "interval": interval,
                    "capabilities": cap,
                    "channel": channel,
                    "vendor": vendor_tag
                }

                self.fingerprint_learned = True
                logging.info(f"📡 Learned fingerprint for {ssid} ({bssid})")
                logging.info(f"➡ Interval: {interval} | Capabilities: {cap} | Channel: {channel} | Vendor: {vendor_tag}")

            except Exception as e:
                logging.error(f"Failed to learn fingerprint: {e}")


    def analyze_recent_activity(self, attack_rssi, attack_time, tolerance=3, window=120):
        """
        Search for devices active near the attack time with similar RSSI.
        """
        suspects = set()
        for entry in self.client_activity:
            if abs(entry["rssi"] - attack_rssi) <= tolerance and (attack_time - entry["time"]) <= window:
                suspects.add(entry["mac"])

        self.attackers_address = suspects
        if not suspects:
            logging.info("NO SUSPECT DETCTED")
        for mac in suspects:
            send_telegram_alert(f"🚨[SUSPECT] {mac} matched deauth RSSI pattern")
            logging.warning(f"[SUSPECT] {mac} matched deauth RSSI pattern")
            with open("logs/alerts.log", "a") as f:
                f.write(f"[SUSPECT] {mac} seen near deauth RSSI {attack_rssi}\n")
    
    def detect_rogue_ap(self, pkt):
        """Detect Evil Twin AP mimicking OUR AP but with mismatched fingerprint."""
        if not pkt.haslayer(Dot11Beacon):
            return

        bssid = pkt.addr2
        elt = pkt.getlayer(Dot11Elt)

        try:
            ssid = elt.info.decode('utf-8', errors='ignore').strip()
        except Exception:
            return

        # Skip unrelated SSIDs
        if ssid != self.ap_ssid:
            return

        if not self.fingerprint_learned:
            return

        try:
            interval = pkt[Dot11Beacon].beacon_interval
            cap = pkt.sprintf("{Dot11Beacon: %Dot11Beacon.cap%}")
            channel = None
            vendor_tag = None
            current = elt

            while isinstance(current, Dot11Elt):
                if current.ID == 3:
                    try:
                        channel = ord(current.info)
                    except:
                        channel = None
                elif current.ID == 221:
                    vendor_tag = current.info.hex()
                current = current.payload

        except Exception as e:
            logging.error(f"[!] Error extracting beacon fingerprint: {e}")
            return

        mismatch = []
        real_fp = self.real_fingerprint

        # Only react to beacons pretending to be OUR BSSID
        if bssid.lower() != YOUR_AP_BSSID.lower():
            mismatch.append("BSSID")
        if interval != real_fp.get("interval"):
            mismatch.append("interval")
        if cap != real_fp.get("capabilities"):
            mismatch.append("capabilities")
        if channel and real_fp.get("channel") and channel != real_fp.get("channel"):
            mismatch.append("channel")
        if vendor_tag != real_fp.get("vendor"):
            mismatch.append("vendor tag")

        if mismatch:
            now = time.time()

            if not self.evil_twin_detected:
                self.evil_twin_detected = True
                self.evil_twin_start_time = now
                self.evil_twin_packets = [pkt]

                logging.critical(
                    f"EVIL TWIN DETECTED | BSSID: {bssid} | SSID: {ssid} | Mismatches: {', '.join(mismatch)}"
                )
                self.capture_attack_packets(duration=10, attack_type="evil_twin")
                send_telegram_alert("🚨 *Evil twin Attack Detected!* Check logs and saved PCAP.")
            elif now - self.evil_twin_start_time > 120:
                self.evil_twin_detected = False
                
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
        # and rssi is not None:
            # print(f"\n{rssi}\n") 
            # print("RSSI KAYNE")
            # self.analyze_recent_activity(rssi, now)
        

            self.capture_attack_packets(duration=10, attack_type="deauth")
            send_telegram_alert("🚨 *Deauth Attack Detected!* Check logs and saved PCAP.")
            logging.critical(
                f"DEAUTH ATTACK DETECTED!"
                f"  Claimed source: {claimed_src}"
                f"  Attacker mac: {attacker_mac}"
                f"  Target: {dst_mac}"
            )
        #capturing packets for forensics    
        # if self.deauth_attack_active:
        #     if now - self.deauth_attack_start <= 10:
        #         self.deauth_packets.append(pkt)
        #     else:
        #         timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        #         capture_dir = os.path.join(os.path.dirname(__file__), "captures")
        #         os.makedirs(capture_dir, exist_ok=True)
        #         pcap_path = os.path.join(capture_dir, f"deauth attack {timestamp}.pcap")

        #         try:
        #             wrpcap(pcap_path, self.deauth_packets)
        #             logging.info(f"[+] Saved deauth attack capture to: {pcap_path}")
        #         except Exception as e:
        #             logging.error(f"[!] Failed to save deauth pcap: {e}")

        #         # Cleanup
        #         self.deauth_attack_active = False
        #         self.deauth_attack_start = None
        #         self.deauth_packets = []

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



    def load_whitelist(self, filepath=None):
        """
        Load whitelist from a file, creating the file if it doesn't exist.
        
        Args:
            filepath (str, optional): Path to the whitelist file. 
                                      Defaults to ./logs/whitelist.txt
        """
        # Ensure logs directory exists
        logs_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(logs_dir, exist_ok=True)

        # Default filepath if not provided
        if filepath is None:
            filepath = os.path.join(logs_dir, "whitelist.txt")

        try:
            # Create the file if it doesn't exist
            if not os.path.exists(filepath):
                with open(filepath, 'w', encoding='utf-8') as f:
                    logging.info(f"Created new whitelist file at {filepath}")
                # Initialize with an empty set
                self.whitelist = set()
                return

            # Read the file
            with open(filepath, 'r', encoding='utf-8') as f:
                # Validate MAC address format while reading
                self.whitelist = set()
                for line in f:
                    mac = line.strip().lower()
                    # Simple MAC address format validation
                    if mac and self._is_valid_mac(mac):
                        self.whitelist.add(mac)
                    elif mac:
                        logging.warning(f"Invalid MAC address format: {mac}")

            logging.info(f"Loaded whitelist with {len(self.whitelist)} valid entries from {filepath}")

        except IOError as e:
            logging.error(f"IO Error reading whitelist file {filepath}: {e}")
            self.whitelist = set()
        except Exception as e:
            logging.error(f"Unexpected error loading whitelist: {e}")
            self.whitelist = set()

    def _is_valid_mac(self, mac):
        """
        Validate MAC address format.
        
        Args:
            mac (str): MAC address to validate
        
        Returns:
            bool: True if MAC address is valid, False otherwise
        """
        # Regular MAC address formats:
        # 1. XX:XX:XX:XX:XX:XX
        # 2. XX-XX-XX-XX-XX-XX
        # 3. XXXXXXXXXXXX
        import re
        mac_regex = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^([0-9A-Fa-f]{12})$'
        return re.match(mac_regex, mac) is not None
    
    def _update_client_state(self, client_mac, current_time, rssi_str, status, frame_type):
        """
        helper method to update client state, detect new clients,
        and flag untrusted devices.
        """
        existing_client = self.find_client_by_mac(client_mac)
        self.load_whitelist()
        # print(f"\n{self.whitelist}\n")
        is_whitelisted = client_mac in self.whitelist
        if not existing_client:
            # New client detected
            new_client = {
                'mac': client_mac,
                'first_seen': current_time,
                'last_seen': current_time,
                'rssi': rssi_str,
                'status': status,
                'whitelisted': is_whitelisted,
                'is_new': True
            }
            self.connected_clients.append(new_client)

            # Log & alert if not trusted
            self._log_client_event(client_mac, f"NEW {status}", rssi_str, "", "", frame_type)
            if not is_whitelisted:
                logging.warning(f"New untrusted client detected: {client_mac}")
                send_telegram_alert(f"⚠️ *Untrusted Client Connected!*\nMAC: `{client_mac}`\nStatus: `{status}`")

        else:
            # Update existing client info
            existing_client['last_seen'] = current_time
            if rssi_str != "N/A":
                existing_client['rssi'] = rssi_str
            existing_client['is_new'] = False  # It's no longer new

            # Status promotion logic
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
            if not self.channel_updated:
                self.update_ap_channel(pkt)
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

            now = time.time()
            if pkt.haslayer(Dot11) and pkt.haslayer(RadioTap):
                mac = pkt.addr2.lower() if pkt.addr2 else None
                rssi = getattr(pkt[RadioTap], 'dBm_AntSignal', None)
                frame_type = pkt.subtype if hasattr(pkt, 'subtype') else 'unknown'

                if mac and rssi is not None:
                    self.client_activity.append({
                        "mac": mac,
                        "rssi": rssi,
                        "time": now,
                        "frame_type": frame_type
                    })

            # Remove entries older than 2 minutes
            while self.client_activity and now - self.client_activity[0]["time"] > 120:
                self.client_activity.popleft()
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