import re
import requests
import os
import threading
from fortigate import get_group_objects, execute_fortigate_command
from dotenv import load_dotenv

# Ortam değişkenlerini yükle
load_dotenv()

# 🛡️ AbuseIPDB ve VirusTotal API Entegrasyonu
class SecurityScanner:
    def __init__(self):
        self.abuse_ipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.vt_headers = {"accept": "application/json", "x-apikey": self.virustotal_key}
        self.abuse_headers = {"Accept": "application/json", "Key": self.abuse_ipdb_key}

    def scan_ip(self, ip):
        """IP adresini AbuseIPDB ve VirusTotal ile tarar."""
        abuse_score = self.scan_abuse_ipdb(ip)
        vt_score = self.scan_virustotal(ip)
        return abuse_score, vt_score

    def scan_abuse_ipdb(self, ip):
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
        response = requests.get(url, headers=self.abuse_headers, params=querystring)
        if response.status_code == 200:
            return response.json().get("data", {}).get("abuseConfidenceScore", 0)
        return 0

    def scan_virustotal(self, ip):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(url, headers=self.vt_headers)
        if response.status_code == 200:
            return response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        return 0

# 🛡️ Fortigate IP Yönetimi
class FortigateManager:
    def __init__(self):
        self.scanner = SecurityScanner()
        self.default_removal_time = 120  # 12 saat (43200 saniye)
        self.address_group_name = "AutomationBlacklist"  # IP'lerin ekleneceği grup

    def add_ip_to_blacklist(self, ip):
        """IP'yi AutomationBlacklist grubuna ekleyip belirlenen sürede kaldırır."""
        # Mevcut grup adlarını kontrol et
        existing_groups = get_group_objects()
        if self.address_group_name not in existing_groups:
            print(f"Hata: {self.address_group_name} grubu bulunamadı!")
            return

        address_name = f"AutomationBlacklist-{ip}"
        create_address_command = f"""
        config firewall address
            edit "{address_name}"
                set subnet {ip} 255.255.255.255
            next
        end
        """
        add_to_group_command = f"""
        config firewall addrgrp
            edit "{self.address_group_name}"
                append member "{address_name}"
            next
        end
        """

        print(f"🚨 {ip} {self.address_group_name} grubuna ekleniyor...")
        execute_fortigate_command(create_address_command)
        execute_fortigate_command(add_to_group_command)

        # IP otomatik olarak 12 saat (43200 saniye) sonra kaldırılacak
        threading.Timer(self.default_removal_time, self.remove_ip_from_blacklist, [address_name]).start()
        print(f"⏳ {ip} 12 saat sonra {self.address_group_name} grubundan otomatik olarak kaldırılacak.")

    def remove_ip_from_blacklist(self, address_name):
        """AutomationBlacklist grubundan belirlenen IP'yi kaldırır."""
        remove_command = f"""
        config firewall addrgrp
            edit "{self.address_group_name}"
                unselect member "{address_name}"
            next
        end
        """
        print(f"⏳ {address_name} kaldırılıyor {self.address_group_name} grubundan...")
        execute_fortigate_command(remove_command)

# 🛡️ Otomatik Analiz ve Blacklist Entegrasyonu
def analyze_and_blacklist():
    fortigate_manager = FortigateManager()

    while True:
        ip_input = input("İncelenecek IP adresini girin (çıkmak için 'exit'): ").strip()
        if ip_input.lower() == 'exit':
            print("Çıkış yapılıyor...")
            break

        if not re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ip_input):
            print("⚠️ Geçersiz IP formatı, lütfen geçerli bir IP adresi girin.")
            continue

        abuse_score, vt_score = fortigate_manager.scanner.scan_ip(ip_input)

        print(f"🔍 {ip_input} - AbuseIPDB Score: {abuse_score}, VirusTotal Malicious: {vt_score}")

        if abuse_score > 50 or vt_score > 3:
            print(f"⚠️ {ip_input} şüpheli bulundu, {fortigate_manager.address_group_name} grubuna ekleniyor...")
            fortigate_manager.add_ip_to_blacklist(ip_input)
        else:
            print(f"✅ {ip_input} güvenli görünüyor, işlem yapılmadı.")

# 🚀 Ana Çalıştırma Bloğu
if __name__ == "__main__":
    analyze_and_blacklist()
