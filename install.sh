#!/bin/bash

set -euo pipefail

GREEN="\e[32m"
BOLD="\e[1m"
RESET="\e[0m"

# Log dosyası tanımı ve log fonksiyonları
LOG_FILE="/var/log/ipv6proxy_install.log"

log() {
    # Hem ekrana hem log dosyasına yaz
    echo -e "${GREEN}${BOLD}$1${RESET}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

error_exit() {
    # Hata durumunda hem ekrana hem log dosyasına yazıp çık
    echo -e "${BOLD}\e[31m$1${RESET}" >&2
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
    exit 1
}

# 3proxy konfigürasyonu ve IPv6 atamalarını yedekle
backup_configs() {
    log "3proxy konfigürasyonu ve IPv6 atamalarının yedeği alınıyor..."
    cp /etc/3proxy/3proxy.cfg /etc/3proxy/3proxy.cfg.bak 2>>"$LOG_FILE" || log "/etc/3proxy/3proxy.cfg yedeklenemedi."
    ip -6 addr show | grep inet6 | awk '{print $2, $NF}' > /root/ipv6-assigned.bak 2>>"$LOG_FILE" || log "IPv6 atamaları yedeklenemedi."
    log "Yedekleme tamamlandı."
}

# Yedekten geri yükleme işlemi
restore_configs() {
    log "Yedekler geri yükleniyor..."
    if [ -f /etc/3proxy/3proxy.cfg.bak ]; then
        cp /etc/3proxy/3proxy.cfg.bak /etc/3proxy/3proxy.cfg
        log "3proxy.cfg geri yüklendi."
    fi
    if [ -f /root/ipv6-assigned.bak ]; then
        while read -r addr iface; do
            ip -6 addr add "$addr" dev "$iface" 2>>"$LOG_FILE" || log "$addr $iface atanamadı."
        done < /root/ipv6-assigned.bak
        log "IPv6 adresleri geri yüklendi."
    fi
}

whiptail_prompt() {
    local message="$1"
    local title="$2"
    whiptail --inputbox "$message" 8 78 --title "$title" 3>&1 1>&2 2>&3
}

install_packages() {
    if command -v apt >/dev/null 2>&1; then
        apt-get update >>"$LOG_FILE" 2>&1 || error_exit "apt-get update başarısız."
        apt-get install -y wget whiptail iproute2 >>"$LOG_FILE" 2>&1 || error_exit "Gerekli paketler kurulamadı (apt)."
        wget https://github.com/3proxy/3proxy/releases/download/0.9.5/3proxy-0.9.5.x86_64.deb >>"$LOG_FILE" 2>&1 || error_exit "3proxy deb indirilemedi."
        dpkg -i 3proxy-0.9.5.x86_64.deb >>"$LOG_FILE" 2>&1 || apt-get install -f -y >>"$LOG_FILE" 2>&1 || error_exit "3proxy kurulumu başarısız (apt)."
    elif command -v dnf >/dev/null 2>&1; then
        dnf update -y >>"$LOG_FILE" 2>&1 || error_exit "dnf update başarısız."
        dnf install -y wget dialog iproute >>"$LOG_FILE" 2>&1 || error_exit "Gerekli paketler kurulamadı (dnf)."
        wget https://github.com/3proxy/3proxy/releases/download/0.9.5/3proxy-0.9.5.x86_64.rpm >>"$LOG_FILE" 2>&1 || error_exit "3proxy rpm indirilemedi."
        rpm -ivh 3proxy-0.9.5.x86_64.rpm >>"$LOG_FILE" 2>&1 || error_exit "3proxy kurulumu başarısız (dnf)."
    elif command -v yum >/dev/null 2>&1; then
        yum update -y >>"$LOG_FILE" 2>&1 || error_exit "yum update başarısız."
        yum install -y wget dialog iproute >>"$LOG_FILE" 2>&1 || error_exit "Gerekli paketler kurulamadı (yum)."
        wget https://github.com/3proxy/3proxy/releases/download/0.9.5/3proxy-0.9.5.x86_64.rpm >>"$LOG_FILE" 2>&1 || error_exit "3proxy rpm indirilemedi."
        rpm -ivh 3proxy-0.9.5.x86_64.rpm >>"$LOG_FILE" 2>&1 || error_exit "3proxy kurulumu başarısız (yum)."
    elif command -v zypper >/dev/null 2>&1; then
        zypper refresh >>"$LOG_FILE" 2>&1 || error_exit "zypper refresh başarısız."
        zypper install -y wget dialog iproute2 >>"$LOG_FILE" 2>&1 || error_exit "Gerekli paketler kurulamadı (zypper)."
        wget https://github.com/3proxy/3proxy/releases/download/0.9.5/3proxy-0.9.5.x86_64.rpm >>"$LOG_FILE" 2>&1 || error_exit "3proxy rpm indirilemedi."
        rpm -ivh 3proxy-0.9.5.x86_64.rpm >>"$LOG_FILE" 2>&1 || error_exit "3proxy kurulumu başarısız (zypper)."
    else
        error_exit "❌ Desteklenmeyen sistem. APT, DNF, YUM, ZYPPER bulunamadı."
    fi
}

[[ "$(id -u)" -ne 0 ]] && { echo "❌ Script root olarak çalıştırılmalıdır."; exit 1; }

if [ ! -f /ipv6lw ]; then
    log "İlk kurulum tespit edildi, gerekli paketler kuruluyor..."
    install_packages
    touch /ipv6lw
    log "Kurulum tamamlandı."
fi

# Script başında kullanıcıya işlem seçtiren menü
CHOICE=$(whiptail --title "İşlem Seçin" --menu "Ne yapmak istersiniz?" 15 60 4 \
"INSTALL" "Kurulum / Güncelleme" \
"BACKUP" "Yedek Al" \
"RESTORE" "Yedekten Geri Yükle (config + IPv6)" \
"EXIT" "Çıkış" 3>&1 1>&2 2>&3)

case $CHOICE in
    INSTALL)
        log "Kurulum veya güncelleme başlatılıyor..."
        ;;
    BACKUP)
        backup_configs
        log "Yedekleme işlemi tamamlandı. Script sonlandırılıyor."
        exit 0
        ;;
    RESTORE)
        restore_configs
        log "Geri yükleme işlemi tamamlandı. Script sonlandırılıyor."
        exit 0
        ;;
    EXIT)
        log "Kullanıcı tarafından çıkış seçildi. Script sonlandırılıyor."
        exit 0
        ;;
esac

AuthType=$(whiptail --title "Kimlik Doğrulama Türü" --menu "Bir kimlik doğrulama yöntemi seçin:" 15 60 2 \
"PASS" "Kullanıcı adı / şifre ile" \
"IP" "IP Whitelist (şifresiz)" 3>&1 1>&2 2>&3)

ProxyType=$(whiptail --title "Proxy Türü" --menu "Bir proxy türü seçin:" 15 60 2 \
"HTTP" "HTTP/HTTPS Proxy" \
"SOCKS5" "SOCKS5 Proxy" 3>&1 1>&2 2>&3)

LogEnable=$(whiptail --title "Loglama Ayarı" --menu "Log açılsın mı?" 10 60 2 \
"YES" "Evet, proxy erişimleri loglansın" \
"NO" "Hayır, log tutulmasın" 3>&1 1>&2 2>&3)

Interfaces=($(ip -o link show | awk -F': ' '{print $2}' | grep -v lo))
IF_MENU=()
for iface in "${Interfaces[@]}"; do
    IF_MENU+=("$iface" " ")
done

Interface=$(whiptail --title "Ağ Arayüzü" --menu "IPv6 atanacak arayüzü seçin:" 20 78 10 "${IF_MENU[@]}" 3>&1 1>&2 2>&3)

IPv6=$(ip -6 addr show dev "$Interface" scope global | grep -oP 'inet6 \K[0-9a-f:]+(?=/)' | head -n1)
[[ -z "$IPv6" ]] && { echo "❌ Bu arayüzde global bir IPv6 adresi bulunamadı."; exit 1; }

IPv6_Base=$(echo "$IPv6" | awk -F: '{printf "%s:%s:%s:%s", $1, $2, $3, $4}')
ProxyCount=$(whiptail_prompt "Kaç adet proxy oluşturulsun?" "Proxy Sayısı")

if [[ "$AuthType" == "PASS" ]]; then
    UserName=$(whiptail_prompt "Kullanıcı adı girin" "Proxy Auth")
    Password=$(whiptail_prompt "Şifre girin" "Proxy Auth")
else
    AllowIP=$(whiptail_prompt "Erişime izin verilecek IP adresini girin" "IP Whitelist")
fi

log "IPv6 adresleri oluşturuluyor..."
IPv6_Array=()
for ((i = 1; i <= ProxyCount; i++)); do
    IPv6_Array+=("$IPv6_Base::$(printf '%x' $i)")
done

log "3proxy yapılandırması oluşturuluyor..."
CONFIG_FILE="/etc/3proxy/3proxy.cfg"
cat <<EOF > "$CONFIG_FILE"
daemon
nserver 1.1.1.1
maxconn 200
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
setgid 65535
setuid 65535
internal 0.0.0.0
flush
EOF

[[ "$LogEnable" == "YES" ]] && echo "log /var/log/3proxy.log D" >> "$CONFIG_FILE"

if [[ "$AuthType" == "PASS" ]]; then
    echo -e "auth strong\nusers $UserName:CL:$Password\nallow $UserName" >> "$CONFIG_FILE"
else
    echo -e "auth iponly\nallow * $AllowIP" >> "$CONFIG_FILE"
fi

Port=30000
for ip in "${IPv6_Array[@]}"; do
    ((Port++))
    if [[ "$ProxyType" == "SOCKS5" ]]; then
        echo "socks -6 -n -a -p$Port -e$ip" >> "$CONFIG_FILE"
    else
        echo "proxy -6 -n -a -p$Port -e$ip" >> "$CONFIG_FILE"
    fi
done

log "$Interface arayüzüne IPv6 adresleri atanıyor..."
for ip in "${IPv6_Array[@]}"; do
    ip -6 addr add "$ip/64" dev "$Interface" || echo "⚠️ $ip atanamadı, atla"
done

log "3proxy yeniden başlatılıyor..."
systemctl restart 3proxy

log "Proxy Listesi:"
[[ "$AuthType" == "PASS" ]] && {
    echo "Kullanıcı Adı: $UserName"
    echo "Şifre: $Password"
} || {
    echo "İzinli IP: $AllowIP"
}

Port=30000
for ip in "${IPv6_Array[@]}"; do
    ((Port++))
    echo "TCP/$Port    IPv6: $ip"
done

log "Kurulum tamamlandı."
exit 0
