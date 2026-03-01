# Network-Scanner-ARP
Python ve Scapy kütüphanesi kullanılarak geliştirilmiş, ARP protokolü tabanlı ağ keşif ve cihaz tespit aracı yerel ağlardaki cihazların tespiti, MAC adresi eşleştirmesi ve donanım üreticisi (Vendor) analizi için geliştirilmiş profesyonel bir ağ keşif aracıdır.

## 🚀 Teknik Özellikler
- **Layer 2 Discovery:** ARP (Address Resolution Protocol) kullanarak hızlı ve güvenilir cihaz tespiti.
- **Vendor Detection:** MAC adresi üzerinden donanım üreticisi (Apple, Samsung, Intel vb.) tespiti.
- **Smart IP Sorting:** Tespit edilen cihazların IP adresine göre nümerik olarak sıralanması.
- **Automated Subnetting:** Sistemin aktif IP adresinden otomatik olarak tarama aralığı (Subnet) üretme.
- **Hostname Resolution:** IP adreslerinden DNS üzerinden cihaz isimlerinin çözümlenmesi.

## 🛠️ Kullanılan Teknolojiler & Kütüphaneler
- **Python 3**
- **Scapy:** Paket manipülasyonu ve ağ trafiği analizi.
- **Manuf:** MAC adresi veritabanı sorguları.
- **Getmac:** Yerel cihaz bilgilerinin yakalanması.

## 📖 Kullanım
```bash
sudo python3 wi-fi scanner.py --subnet 192.168.1.0/24 --timeout 2

⚖️ Yasal Uyarı
Bu araç tamamen siber güvenlik farkındalığı ve yetkili ağlarda sızma testi (pentest) çalışmaları için geliştirilmiştir. Yetkisiz ağlarda kullanımı yasal sorumluluk doğurabilir.
---
