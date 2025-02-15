import threading
from fortigate import get_group_objects, execute_fortigate_command
from checkpoint import login, logout

def show_group_objects():
    """Mevcut Blacklist Grup Objelerini Göster"""
    group_names = get_group_objects()
    if group_names:
        print("Mevcut Blacklist Grup Objeleri:")
        for i, name in enumerate(group_names, 1):
            print(f"{i}. {name}")
    else:
        print("Blacklist içeren adres grupları bulunamadı.")

def remove_ip_from_group(address_name, address_group_name):
    """Belirli bir süreden sonra IP'yi gruptan kaldır"""
    remove_command = f"""
    config firewall addrgrp
        edit "{address_group_name}"
            unselect member "{address_name}"
        next
    end
    """
    print(f"Belirlenen sürede {address_name} kaldırılıyor {address_group_name} grubundan...")
    execute_fortigate_command(remove_command)

def add_ip_to_group():
    """Kullanıcıdan IP alıp gruba ekler."""
    ip_address = input("IP adresini girin (ör. 10.10.10.10): ")
    subnet_mask = input("Subnet mask girin (varsayılan: 255.255.255.255): ") or "255.255.255.255"
    address_group_name = input("Adres grubu ismini girin (ör. Address_Group_Name): ")

    existing_groups = get_group_objects()
    if address_group_name not in existing_groups:
        print("Hata: Bu grup objesi bulunamadı! Lütfen geçerli bir Blacklist grup adı girin.")
        return

    address_name = f"Blacklist-{ip_address}/{subnet_mask}" if subnet_mask != "255.255.255.255" else f"Blacklist-{ip_address}"

    create_address_command = f"""
    config firewall address
        edit "{address_name}"
            set subnet {ip_address} {subnet_mask}
        next
    end
    """

    add_to_group_command = f"""
    config firewall addrgrp
        edit "{address_group_name}"
            append member "{address_name}"
        next
    end
    """

    print("Adres objesi oluşturuluyor...")
    execute_fortigate_command(create_address_command)

    print("Adres objesi gruba ekleniyor...")
    execute_fortigate_command(add_to_group_command)

    print("IP başarıyla eklendi! Süre seçin:")
    print("1: 2 dakika")
    print("2: 1 saat")
    print("3: 12 saat")
    print("4: 24 saat")
    print("5: Permanently (Kalıcı)")

    duration_choice = input("Seçiminizi yapın: ")
    durations = {"1": 120, "2": 3600, "3": 43200, "4": 86400}

    if duration_choice in durations:
        delay = durations[duration_choice]
        threading.Timer(delay, remove_ip_from_group, [address_name, address_group_name]).start()
        print(f"IP {delay} saniye sonra {address_group_name} grubundan kaldırılacak.")
    else:
        print("IP kalıcı olarak eklendi.")

if __name__ == "__main__":
    while True:
        print("\n1: Show Blacklist group objects")
        print("2: Enter IP address")
        print("3: Exit")

        choice = input("Seçeneğinizi girin: ")
        if choice == "1":
            show_group_objects()
        elif choice == "2":
            add_ip_to_group()
        elif choice == "3":
            print("Çıkış yapılıyor...")
            break
        else:
            print("Geçersiz seçenek. Lütfen tekrar deneyin.")
