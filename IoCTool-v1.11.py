import re
import requests
import json
import pandas as pd
from tabulate import tabulate
from dotenv import load_dotenv
import os

# Ortam değişkenlerini yükle
load_dotenv()

# 🛡️ URLScan API Entegrasyonu
class URLScan:
    def __init__(self):
        self.api_key = os.getenv("URLSCAN_API_KEY")
        self.headers = {'API-Key': self.api_key, 'Content-Type': 'application/json'}

    def search_url(self, url):
        response = requests.get(f'https://urlscan.io/api/v1/search/?q=domain:{url}')
        return self.handle_response(response)

    @staticmethod
    def handle_response(response):
        return response.json() if response.status_code == 200 else {"error": f"Request failed with status {response.status_code}"}

# 🛡️ AbuseIPDB API Entegrasyonu
class AbuseIPDB:
    def scan_ip(self, ip_address):
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json', 'Key': os.getenv("ABUSEIPDB_API_KEY")}
        response = requests.get(url, headers=headers, params=querystring)
        return self.handle_response(response)

    def scan_domain(self, domain):
        url = f'https://api.abuseipdb.com/api/v2/check-domain'
        querystring = {'domain': domain, 'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json', 'Key': os.getenv("ABUSEIPDB_API_KEY")}
        response = requests.get(url, headers=headers, params=querystring)
        return self.handle_response(response)

    @staticmethod
    def handle_response(response):
        return response.json() if response.status_code == 200 else {"error": f"Request failed with status {response.status_code}"}

# 🛡️ VirusTotal API Entegrasyonu
class VirusTotal:
    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.headers = {"accept": "application/json", "x-apikey": self.api_key}

    def scan_domain(self, domain):
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=self.headers)
        return self.handle_response(response)

    def scan_ip(self, ip):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(url, headers=self.headers)
        return self.handle_response(response)

    @staticmethod
    def handle_response(response):
        return response.json() if response.status_code == 200 else {"error": f"Request failed with status {response.status_code}"}

# 🎯 Ana Uygulama Sınıfı
class ConsoleApp:
    def __init__(self):
        self.urlscan = URLScan()
        self.abuse_ipdb = AbuseIPDB()
        self.virus_total = VirusTotal()

    def summarize_virustotal(self, vt_data):
        """ VirusTotal verisini özetleyerek tablo haline getirir """
        try:
            attributes = vt_data.get("data", {}).get("attributes", {})
            summary_data = {
                "Reputation": attributes.get("reputation", "N/A"),
                "Categories": ", ".join(attributes.get("categories", {}).values()),
                "Malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "Suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "Harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "Undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
            }
            df_vt = pd.DataFrame(list(summary_data.items()), columns=["Attribute", "Value"])
            return df_vt
        except Exception as e:
            return pd.DataFrame([["Error", str(e)]], columns=["Attribute", "Value"])

    def summarize_abuseipdb(self, abuse_data):
        """ AbuseIPDB verisini tablo formatına dönüştürür """
        try:
            attributes = abuse_data.get("data", {})
            summary_data = {
                "IP/Domain": attributes.get("ipAddress", attributes.get("domain", "N/A")),
                "Country": attributes.get("countryCode", "N/A"),
                "ISP": attributes.get("isp", "N/A"),
                "Usage Type": attributes.get("usageType", "N/A"),
                "Abuse Score": attributes.get("abuseConfidenceScore", 0),
                "Total Reports": attributes.get("totalReports", 0),
                "Distinct Users": attributes.get("numDistinctUsers", 0),
                "Last Reported": attributes.get("lastReportedAt", "N/A"),
            }
            df_abuse = pd.DataFrame(list(summary_data.items()), columns=["Attribute", "Value"])
            return df_abuse
        except Exception as e:
            return pd.DataFrame([["Error", str(e)]], columns=["Attribute", "Value"])

    def process_input(self, user_input):
        if re.match(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', user_input):
            print("🔎 Detected domain. Querying VirusTotal, URLScan, and AbuseIPDB...")
            vt_data = self.virus_total.scan_domain(user_input)
            abuse_data = self.abuse_ipdb.scan_domain(user_input)
            df_results_vt = self.summarize_virustotal(vt_data)
            df_results_abuse = self.summarize_abuseipdb(abuse_data)
            print(tabulate(df_results_vt, headers='keys', tablefmt='grid'))
            print(tabulate(df_results_abuse, headers='keys', tablefmt='grid'))
        elif re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_input):
            print("🔎 Detected IP address. Querying VirusTotal and AbuseIPDB...")
            vt_data = self.virus_total.scan_ip(user_input)
            abuse_data = self.abuse_ipdb.scan_ip(user_input)
            df_results_vt = self.summarize_virustotal(vt_data)
            df_results_abuse = self.summarize_abuseipdb(abuse_data)
            print(tabulate(df_results_vt, headers='keys', tablefmt='grid'))
            print(tabulate(df_results_abuse, headers='keys', tablefmt='grid'))
        else:
            print("⚠️ Invalid input. Please enter a valid domain or IP address.")

    def run(self):
        while True:
            user_input = input("🔹 Enter a domain or IP (or type 'exit' to quit): ").strip()
            if user_input.lower() == 'exit':
                print("👋 Exiting the tool. Have a great day!")
                break
            self.process_input(user_input)

# 🚀 Ana Program Çalıştırma
if __name__ == '__main__':
    app = ConsoleApp()
    app.run()