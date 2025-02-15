import paramiko
import configparser
import re

# Config dosyasını oku
config = configparser.ConfigParser()
config.read("config.ini")

try:
    fortigate_ip = config.get("FortiGate", "fortigate_ip")
    fortigate_username = config.get("FortiGate", "username")
    fortigate_password = config.get("FortiGate", "password")
except configparser.Error as e:
    print(f"Error reading config file: {e}")
    exit()

def execute_fortigate_command(command):
    """FortiGate üzerinde komut çalıştırır."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(fortigate_ip, username=fortigate_username, password=fortigate_password)

        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()

        ssh.close()
        if error:
            print(f"Error: {error}")
        return output
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def get_group_objects():
    """Blacklist içeren grup objelerini getirir."""
    command = "show firewall addrgrp"
    output = execute_fortigate_command(command)
    if output:
        groups = sorted(re.findall(r'edit \"([^\"]+)\"', output))
        return [group for group in groups if re.search(r'blacklist', group, re.IGNORECASE)]
    return []
