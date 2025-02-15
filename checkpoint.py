import requests
import configparser

# Config dosyasını oku
config = configparser.ConfigParser()
config.read("config.ini")

try:
    api_url = config.get("Checkpoint", "api_url")
    username = config.get("Checkpoint", "username")
    password = config.get("Checkpoint", "password")
except configparser.Error as e:
    print(f"Error reading config file: {e}")
    exit()

# Sertifika doğrulamasını kapat
requests.packages.urllib3.disable_warnings()

def login():
    """Checkpoint'e giriş yap ve oturum aç."""
    payload = {"user": username, "password": password}
    response = requests.post(f"{api_url}/login", json=payload, verify=False)
    if response.status_code == 200:
        return response.json()["sid"]
    else:
        print("Login failed:", response.json())
        exit()

def logout(sid):
    """Checkpoint'ten çıkış yap."""
    headers = {"Content-Type": "application/json", "X-chkp-sid": sid}
    requests.post(f"{api_url}/logout", headers=headers, verify=False)
    print("🔒 Logged out.")
