#!/usr/bin/env python3
# Avci-Scan: Advanced Network Discovery & Asset Mapping Tool
# Geliştiren: avci-cyber

import socket
import time
import argparse
import sys
import os
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

# Ek kütüphaneler için hata yönetimi
try:
    from getmac import get_mac_address as getMacAddress
    from manuf import manuf
except ImportError:
    print("[-] Hata: 'getmac' veya 'manuf' kütüphanesi eksik. Kurmak için: pip install getmac manuf")
    sys.exit(1)

# Konsol Tasarımı
CONSOLE_PREFIX = "[Avci-Scan]"
mac_parser = manuf.MacParser(update=False)

def get_local_ip():
    """Sistemin aktif ağ IP adresini Google DNS üzerinden yakalar."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

def default_subnet_from_ip(local_ip):
    """Local IP'den otomatik /24 subnet maskesi üretir."""
    return ".".join(local_ip.split(".")[:3]) + ".0/24"

def get_vendor(mac):
    """MAC adresinden donanım üreticisi (Vendor) tespiti yapar."""
    try:
        brand = mac_parser.get_manuf(mac)
        return brand if brand else "Unknown Vendor"
    except Exception:
        return "Unknown Vendor"

def get_hostname(ip_addr):
    """IP adresinden DNS üzerinden cihaz ismini (Hostname) bulur."""
    try:
        return socket.gethostbyaddr(ip_addr)[0]
    except (socket.herror, socket.error):
        return None

def arp_scan(subnet, timeout_sec=2, iface=None):
    """ARP protokolü kullanarak ağ taraması gerçekleştirir."""
    print(f"{CONSOLE_PREFIX} Tarama başlatılıyor: {subnet}...")
    start_time = time.perf_counter()
    
    # Layer 2 Paket Oluşturma: Ethernet + ARP
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet))
    
    # Gönder ve Al (Send and Receive)
    answered, _ = srp(packet, timeout=timeout_sec, iface=iface, verbose=False)
    duration = time.perf_counter() - start_time

    device_list = []
    for _, response in answered:
        ip = response.psrc
        mac = response.hwsrc.lower()
        vendor = get_vendor(mac)
        hostname = get_hostname(ip)
        
        device_info = f"{vendor}" + (f" ({hostname})" if hostname else "")
        device_list.append({"ip": ip, "mac": mac, "device": device_info})

    # IP Adresine göre akıllı sıralama
    device_list.sort(key=lambda x: [int(part) for part in x['ip'].split('.')])
    
    return device_list, duration

def main():
    parser = argparse.ArgumentParser(description="Avci-Scan: Profesyonel Ağ Keşif Aracı")
    parser.add_argument("--subnet", help="Hedef IP aralığı (Örn: 192.168.1.0/24)")
    parser.add_argument("--timeout", type=int, default=2, help="Sorgu zaman aşımı (Saniye)")
    args = parser.parse_args()

    # Yetki Kontrolü
    if os.getuid() != 0:
        print(f"{CONSOLE_PREFIX} HATA: ARP taraması için root (sudo) yetkisi gereklidir.")
        sys.exit(1)

    local_ip = get_local_ip()
    target_subnet = args.subnet or default_subnet_from_ip(local_ip)

    print(f"\n{CONSOLE_PREFIX} Host Bilgisi: {local_ip} | {getMacAddress()}")
    print(f"{CONSOLE_PREFIX} Hedef Aralık: {target_subnet}\n")

    results, duration = arp_scan(target_subnet, timeout_sec=args.timeout)

    print(f"\n{'IP ADRESI':<16} {'MAC ADRESI':<20} {'CIHAZ BILGISI'}")
    print("-" * 65)
    for r in results:
        print(f"{r['ip']:<16} {r['mac']:<20} {r['device']}")
    
    print(f"\n{CONSOLE_PREFIX} İşlem Tamamlandı: {len(results)} cihaz bulundu. (Süre: {duration:.2f}s)")

if __name__ == "__main__":
    main()
