#!/bin/bash

set -e
set -u

GREEN="\e[32m"
BOLD="\e[1m"
RESET="\e[0m"

log() {
    echo -e "${GREEN}${BOLD}$1${RESET}"
}

whiptail_prompt() {
    local message="$1"
    local title="$2"
    whiptail --inputbox "$message" 8 78 --title "$title" 3>&1 1>&2 2>&3
}

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Bu script yalnızca root olarak çalıştırılabilir!"
    exit 1
fi

if [ ! -f /ipv6lw ]; then
    log "Script ilk defa çalıştırılıyor olarak tespit edildi, gereki paketler kuruluyor..."

    wget https://github.com/3proxy/3proxy/releases/download/0.9.5/3proxy-0.9.5.x86_64.deb
    dpkg -i 3proxy-0.9.5.x86_64.deb
    apt-get install -f -y
    touch /ipv6lw

    log "Kurulumlar tamamlandı ve /ipv6lw dosyası oluşturuldu."
fi

ProxyType=$(whiptail --title "Proxy Türü" --menu "Bir proxy türü seçin:" 15 60 2 \
"HTTP" "HTTP/HTTPS Proxy" \
"SOCKS5" "SOCKS5 Proxy" 3>&1 1>&2 2>&3)

Interfaces=($(ip -o link show | awk -F': ' '{print $2}' | grep -v lo))
IF_MENU=()
for iface in "${Interfaces[@]}"; do
    IF_MENU+=("$iface" " ")
done

Interface=$(whiptail --title "Ağ Arayüzü Seçimi" --menu "IPv6 atanacak arayüzü seçin:" 20 78 10 "${IF_MENU[@]}" 3>&1 1>&2 2>&3)

IPv6=$(ip -6 addr show dev "$Interface" scope global | grep -oP 'inet6 \K[0-9a-f:]+(?=/)' | head -n1)

if [[ -z "$IPv6" ]]; then
    echo "❌ Bu arayüzde global bir IPv6 adresi bulunamadı. Lütfen elle kontrol et."
    exit 1
fi

IPv6_Base=$(echo "$IPv6" | awk -F: '{printf "%s:%s:%s:%s", $1, $2, $3, $4}')

ProxyCount=$(whiptail_prompt "Kaç adet proxy oluşturulsun?" "Proxy Sayısı")
UserName=$(whiptail_prompt "Proxy kullanıcı adı girin" "Proxy Auth")
Password=$(whiptail_prompt "Proxy şifresi girin" "Proxy Auth")

IPv6_Start=1
IPv6_Array=()

log "IPv6 adresleri oluşturuluyor..."

for ((i = 1; i <= ProxyCount; i++)); do
    IPv6_Array+=("$IPv6_Base::$(printf '%x' $IPv6_Start)")
    ((IPv6_Start++))
done

log "3proxy yapılandırması oluşturuluyor..."

cat <<EOF >/etc/3proxy/3proxy.cfg
daemon
nserver 1.1.1.1
maxconn 100
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
setgid 65535
setuid 65535
internal 0.0.0.0
flush
auth strong
users $UserName:CL:$Password
allow $UserName
EOF

Port=30000
for ip in "${IPv6_Array[@]}"; do
    ((Port++))
    if [[ "$ProxyType" == "SOCKS5" ]]; then
        echo "socks -6 -n -a -p$Port -e$ip" >> /etc/3proxy/3proxy.cfg
    else
        echo "proxy -6 -n -a -p$Port -e$ip" >> /etc/3proxy/3proxy.cfg
    fi
done

log "$Interface arayüzüne IPv6 adresleri atanıyor..."

for ip in "${IPv6_Array[@]}"; do
    ip -6 addr add "$ip/64" dev "$Interface" || echo "⚠️ $ip atanamadı, atla"
done

log "3proxy servisi yeniden başlatılıyor..."
systemctl restart 3proxy

log "Proxy Listesi:"
echo "Kullanıcı Adı: $UserName"
echo "Şifre: $Password"

Port=30000
for ip in "${IPv6_Array[@]}"; do
    ((Port++))
    echo "TCP/$Port    IPv6: $ip"
done
