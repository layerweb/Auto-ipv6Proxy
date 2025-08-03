#!/bin/bash

# Universal IPv6 Proxy Setup Script
# Compatible with all major hosting providers and Linux distributions
# Supports various IPv6 subnet configurations (from /64 to /128)
# GitHub: https://github.com/layerweb/Auto-ipv6Proxy

set -euo pipefail

# Version and metadata
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="Universal IPv6 Proxy Setup"
readonly GITHUB_REPO="https://github.com/layerweb/Auto-ipv6Proxy"

# Color definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly RESET='\033[0m'

# Global variables
declare -a IPv6_Array=()
declare -a Available_Interfaces=()
declare -g Selected_Interface=""
declare -g Selected_IPv6=""
declare -g Subnet_Type=""
declare -g Subnet_Mask=""
declare -g OS_TYPE=""
declare -g OS_VERSION=""
declare -g PACKAGE_MANAGER=""

# Logging functions
log_info() {
    echo -e "${GREEN}${BOLD}[INFO]${RESET} $1"
}

log_warn() {
    echo -e "${YELLOW}${BOLD}[WARN]${RESET} $1"
}

log_error() {
    echo -e "${RED}${BOLD}[ERROR]${RESET} $1"
}

log_success() {
    echo -e "${CYAN}${BOLD}[SUCCESS]${RESET} $1"
}

log_debug() {
    [[ "${DEBUG:-0}" == "1" ]] && echo -e "${PURPLE}[DEBUG]${RESET} $1"
}

# Banner function
show_banner() {
    clear
    echo -e "${BLUE}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║        🌐 UNIVERSAL IPv6 PROXY SETUP v${SCRIPT_VERSION}                ║"
    echo "║                                                              ║"
    echo "║  ✅ Multi-Platform Support (Ubuntu/Debian/CentOS/RHEL)      ║"
    echo "║  ✅ All Hosting Providers (Hetzner/OVH/DO/Vultr/Linode)     ║"
    echo "║  ✅ Smart Subnet Detection (/64 to /128)                    ║"
    echo "║  ✅ HTTP & SOCKS5 Proxy Support                             ║"
    echo "║  ✅ Production Ready & GitHub Compatible                    ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "${GREEN}Repository: ${GITHUB_REPO}${RESET}"
    echo ""
}

# Enhanced whiptail prompt with error handling
whiptail_prompt() {
    local message="$1"
    local title="$2"
    local default="${3:-}"
    
    if ! command -v whiptail >/dev/null 2>&1; then
        echo -n "$message: "
        read -r input
        echo "$input"
        return
    fi
    
    local result
    if [[ -n "$default" ]]; then
        result=$(whiptail --inputbox "$message" 10 60 "$default" --title "$title" 3>&1 1>&2 2>&3 2>/dev/null || echo "")
    else
        result=$(whiptail --inputbox "$message" 10 60 --title "$title" 3>&1 1>&2 2>&3 2>/dev/null || echo "")
    fi
    
    [[ -z "$result" ]] && {
        log_error "Kullanıcı girişi iptal edildi"
        exit 1
    }
    
    echo "$result"
}

# Enhanced whiptail menu with fallback
whiptail_menu() {
    local title="$1"
    local message="$2"
    shift 2
    local options=("$@")
    
    if ! command -v whiptail >/dev/null 2>&1; then
        echo "$message"
        local i=1
        while [[ $i -lt ${#options[@]} ]]; do
            echo "$i) ${options[$i]} - ${options[$((i+1))]}"
            i=$((i+2))
        done
        echo -n "Seçiminiz (1-$((${#options[@]}/2))): "
        read -r choice
        echo "${options[$((choice*2-1))]}"
        return
    fi
    
    whiptail --title "$title" --menu "$message" 20 78 10 "${options[@]}" 3>&1 1>&2 2>&3 2>/dev/null || {
        log_error "Menü seçimi iptal edildi"
        exit 1
    }
}

# Comprehensive OS detection
detect_operating_system() {
    log_info "İşletim sistemi tespit ediliyor..."
    
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/etc/os-release
        . /etc/os-release
        OS_TYPE="$ID"
        OS_VERSION="${VERSION_ID:-unknown}"
    elif [[ -f /etc/redhat-release ]]; then
        OS_TYPE="rhel"
        OS_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1)
    elif [[ -f /etc/debian_version ]]; then
        OS_TYPE="debian"
        OS_VERSION=$(cat /etc/debian_version)
    else
        log_error "Desteklenmeyen işletim sistemi!"
        exit 1
    fi
    
    # Package manager detection
    if command -v apt-get >/dev/null 2>&1; then
        PACKAGE_MANAGER="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PACKAGE_MANAGER="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PACKAGE_MANAGER="yum"
    elif command -v zypper >/dev/null 2>&1; then
        PACKAGE_MANAGER="zypper"
    elif command -v pacman >/dev/null 2>&1; then
        PACKAGE_MANAGER="pacman"
    else
        log_error "Desteklenen paket yöneticisi bulunamadı!"
        exit 1
    fi
    
    log_success "OS: $OS_TYPE $OS_VERSION, Package Manager: $PACKAGE_MANAGER"
}

# Universal package installation
install_system_packages() {
    log_info "Sistem paketleri kuruluyor..."
    
    local base_packages="wget curl net-tools iproute2 iputils-ping"
    local ui_packages=""
    
    # UI packages based on availability
    if command -v whiptail >/dev/null 2>&1; then
        ui_packages="whiptail"
    elif command -v dialog >/dev/null 2>&1; then
        ui_packages="dialog"
    else
        case "$PACKAGE_MANAGER" in
            "apt")
                ui_packages="whiptail"
                ;;
            "dnf"|"yum")
                ui_packages="dialog"
                ;;
            "zypper")
                ui_packages="dialog"
                ;;
            "pacman")
                ui_packages="dialog"
                ;;
        esac
    fi
    
    case "$PACKAGE_MANAGER" in
        "apt")
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            # shellcheck disable=SC2086
            apt-get install -y $base_packages $ui_packages
            ;;
        "dnf")
            dnf update -y -q
            # shellcheck disable=SC2086
            dnf install -y $base_packages $ui_packages
            ;;
        "yum")
            yum update -y -q
            # shellcheck disable=SC2086
            yum install -y $base_packages $ui_packages
            ;;
        "zypper")
            zypper refresh -q
            # shellcheck disable=SC2086
            zypper install -y $base_packages $ui_packages
            ;;
        "pacman")
            pacman -Sy --noconfirm
            # shellcheck disable=SC2086
            pacman -S --noconfirm $base_packages $ui_packages
            ;;
    esac
    
    log_success "Sistem paketleri kuruldu"
}

# Enhanced 3proxy installation with multiple methods
install_3proxy() {
    log_info "3proxy kuruluyor..."
    
    if command -v 3proxy >/dev/null 2>&1; then
        log_warn "3proxy zaten kurulu, güncelleme kontrol edilyor..."
    fi
    
    local install_success=false
    local temp_dir="/tmp/3proxy_install"
    mkdir -p "$temp_dir"
    cd "$temp_dir"
    
    # Method 1: Package manager installation (if available)
    case "$PACKAGE_MANAGER" in
        "apt")
            if apt-cache search 3proxy | grep -q "3proxy"; then
                apt-get install -y 3proxy && install_success=true
            fi
            ;;
        "dnf"|"yum")
            if $PACKAGE_MANAGER list available 3proxy >/dev/null 2>&1; then
                $PACKAGE_MANAGER install -y 3proxy && install_success=true
            fi
            ;;
    esac
    
    # Method 2: Binary installation
    if [[ "$install_success" == "false" ]]; then
        log_info "Binary kurulum deneniyor..."
        
        local arch
        arch=$(uname -m)
        case "$arch" in
            "x86_64"|"amd64")
                arch="x86_64"
                ;;
            "aarch64"|"arm64")
                arch="aarch64"
                ;;
            "armv7l")
                arch="armv7"
                ;;
            *)
                log_warn "Desteklenmeyen mimari: $arch, kaynak koddan derleme gerekebilir"
                arch="x86_64"  # Fallback
                ;;
        esac
        
        local download_urls=(
            "https://github.com/3proxy/3proxy/releases/download/0.9.5/3proxy-0.9.5.$arch.deb"
            "https://github.com/3proxy/3proxy/releases/download/0.9.5/3proxy-0.9.5.$arch.rpm"
            "https://github.com/3proxy/3proxy/releases/download/0.9.4/3proxy-0.9.4.$arch.deb"
            "https://github.com/3proxy/3proxy/releases/download/0.9.4/3proxy-0.9.4.$arch.rpm"
        )
        
        for url in "${download_urls[@]}"; do
            log_debug "Deneniyor: $url"
            if wget -q --timeout=30 "$url"; then
                local filename
                filename=$(basename "$url")
                
                case "$filename" in
                    *.deb)
                        if command -v dpkg >/dev/null 2>&1; then
                            dpkg -i "$filename" 2>/dev/null && install_success=true
                            [[ "$install_success" == "false" ]] && apt-get install -f -y && install_success=true
                        fi
                        ;;
                    *.rpm)
                        if command -v rpm >/dev/null 2>&1; then
                            rpm -ivh "$filename" 2>/dev/null && install_success=true
                        fi
                        ;;
                esac
                
                [[ "$install_success" == "true" ]] && break
            fi
        done
    fi
    
    # Method 3: Source compilation (last resort)
    if [[ "$install_success" == "false" ]]; then
        log_warn "Binary kurulum başarısız, kaynak koddan derleme deneniyor..."
        
        # Install build dependencies
        case "$PACKAGE_MANAGER" in
            "apt")
                apt-get install -y build-essential gcc make
                ;;
            "dnf"|"yum")
                $PACKAGE_MANAGER groupinstall -y "Development Tools"
                $PACKAGE_MANAGER install -y gcc make
                ;;
        esac
        
        if wget -q --timeout=30 "https://github.com/3proxy/3proxy/archive/0.9.5.tar.gz"; then
            tar -xzf 0.9.5.tar.gz
            cd 3proxy-0.9.5
            make -f Makefile.Linux && make -f Makefile.Linux install && install_success=true
        fi
    fi
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
    
    if [[ "$install_success" == "true" ]] && command -v 3proxy >/dev/null 2>&1; then
        log_success "3proxy başarıyla kuruldu"
        3proxy -v 2>/dev/null || log_debug "3proxy version bilgisi alınamadı"
    else
        log_error "3proxy kurulumu başarısız!"
        exit 1
    fi
}

# Advanced IPv6 network analysis
analyze_ipv6_network() {
    log_info "IPv6 ağ yapılandırması analiz ediliyor..."
    
    # Clear previous data
    Available_Interfaces=()
    
    # Get all interfaces with global IPv6 addresses
    local interfaces
    interfaces=$(ip -6 addr show scope global | grep -E "inet6.*global" | awk '{print $NF}' | sort -u)
    
    if [[ -z "$interfaces" ]]; then
        log_error "Global IPv6 adresi bulunan arayüz yok!"
        echo "IPv6 yapılandırmasını kontrol edin:"
        echo "1. ip -6 addr show"
        echo "2. IPv6 forwarding: sysctl net.ipv6.conf.all.forwarding"
        echo "3. Hosting sağlayıcınızın IPv6 ayarları"
        exit 1
    fi
    
    # Analyze each interface
    while IFS= read -r iface; do
        [[ -z "$iface" ]] && continue
        
        # Get all IPv6 addresses for this interface
        local ipv6_addresses
        ipv6_addresses=$(ip -6 addr show dev "$iface" scope global | grep -oP 'inet6 \K[0-9a-f:]+(?=/)')
        
        while IFS= read -r ipv6; do
            [[ -z "$ipv6" ]] && continue
            
            # Get subnet mask
            local subnet_mask
            subnet_mask=$(ip -6 addr show dev "$iface" | grep "$ipv6" | grep -oP '/\K\d+' | head -1)
            [[ -z "$subnet_mask" ]] && subnet_mask=64
            
            # Test connectivity
            if ip -6 route get "$ipv6" >/dev/null 2>&1; then
                Available_Interfaces+=("$iface:$ipv6:$subnet_mask")
                log_debug "Interface: $iface, IPv6: $ipv6, Subnet: /$subnet_mask"
            fi
        done <<< "$ipv6_addresses"
    done <<< "$interfaces"
    
    if [[ ${#Available_Interfaces[@]} -eq 0 ]]; then
        log_error "Kullanılabilir IPv6 arayüzü bulunamadı!"
        exit 1
    fi
    
    log_success "${#Available_Interfaces[@]} adet IPv6 arayüzü tespit edildi"
}

# Intelligent subnet analysis and classification
classify_subnet() {
    local subnet_mask="$1"
    local ipv6="$2"
    
    Subnet_Mask="$subnet_mask"
    
    if [[ $subnet_mask -ge 120 ]]; then
        Subnet_Type="tiny"      # /120-/128: Very limited (1-256 IPs)
        log_warn "Çok küçük subnet tespit edildi (/$subnet_mask). Maksimum 10 proxy önerilir."
    elif [[ $subnet_mask -ge 112 ]]; then
        Subnet_Type="small"     # /112-/119: Small (256-4096 IPs)
        log_warn "Küçük subnet tespit edildi (/$subnet_mask). Maksimum 100 proxy önerilir."
    elif [[ $subnet_mask -ge 96 ]]; then
        Subnet_Type="medium"    # /96-/111: Medium (4K-1M IPs)
        log_info "Orta boyut subnet tespit edildi (/$subnet_mask). 1000+ proxy desteklenir."
    else
        Subnet_Type="large"     # /64-/95: Large (1M+ IPs)
        log_success "Büyük subnet tespit edildi (/$subnet_mask). Sınırsız proxy desteklenir."
    fi
    
    log_debug "Subnet sınıflandırması: $Subnet_Type (/$subnet_mask)"
}

# Advanced IPv6 address generation with multiple strategies
generate_ipv6_addresses() {
    local base_ipv6="$1"
    local count="$2"
    local interface="$3"
    
    log_info "IPv6 adresleri oluşturuluyor... (Hedef: $count adet)"
    
    IPv6_Array=()
    local generation_strategy=""
    
    case "$Subnet_Type" in
        "tiny")
            # Strategy: Increment last hextet carefully
            generation_strategy="increment"
            [[ $count -gt 10 ]] && {
                log_warn "Tiny subnet için proxy sayısı 10 ile sınırlandırıldı"
                count=10
            }
            
            local base_parts
            IFS=':' read -ra base_parts <<< "$base_ipv6"
            local prefix="${base_parts[0]}:${base_parts[1]}:${base_parts[2]}:${base_parts[3]}:${base_parts[4]}:${base_parts[5]}:${base_parts[6]}"
            local last_part="${base_parts[7]:-0}"
            
            # Convert hex to decimal
            local base_num
            base_num=$((16#${last_part:-0}))
            
            for ((i = 1; i <= count; i++)); do
                local new_num=$((base_num + i))
                [[ $new_num -gt 255 ]] && break  # Prevent overflow in /120 subnets
                IPv6_Array+=("$prefix:$(printf '%x' $new_num)")
            done
            ;;
            
        "small")
            # Strategy: Use last two hextets
            generation_strategy="dual_hextet"
            [[ $count -gt 100 ]] && {
                log_warn "Small subnet için proxy sayısı 100 ile sınırlandırıldı"
                count=100
            }
            
            local prefix
            prefix=$(echo "$base_ipv6" | sed -E 's/:[^:]*:[^:]*$//')
            
            for ((i = 1; i <= count; i++)); do
                local high=$((i / 256))
                local low=$((i % 256))
                IPv6_Array+=("$prefix:$(printf '%x:%x' $high $low)")
            done
            ;;
            
        "medium")
            # Strategy: Use last three hextets with smart distribution
            generation_strategy="triple_hextet"
            
            local prefix
            prefix=$(echo "$base_ipv6" | sed -E 's/:[^:]*:[^:]*:[^:]*$//')
            
            for ((i = 1; i <= count; i++)); do
                local high=$((i / 65536))
                local mid=$(((i % 65536) / 256))
                local low=$((i % 256))
                IPv6_Array+=("$prefix:$(printf '%x:%x:%x' $high $mid $low)")
            done
            ;;
            
        "large")
            # Strategy: Use interface identifier with zero compression
            generation_strategy="interface_id"
            
            local prefix
            prefix=$(echo "$base_ipv6" | awk -F: '{printf "%s:%s:%s:%s", $1, $2, $3, $4}')
            
            for ((i = 1; i <= count; i++)); do
                IPv6_Array+=("$prefix::$(printf '%x' $i)")
            done
            ;;
    esac
    
    log_success "Toplam ${#IPv6_Array[@]} IPv6 adresi oluşturuldu ($generation_strategy stratejisi)"
    log_debug "İlk 3 adres: ${IPv6_Array[0]:-}, ${IPv6_Array[1]:-}, ${IPv6_Array[2]:-}"
}

# Robust IPv6 address assignment with validation
assign_ipv6_addresses() {
    local interface="$1"
    shift
    local addresses=("$@")
    
    log_info "IPv6 adresleri $interface arayüzüne atanıyor..."
    
    local success_count=0
    local failed_addresses=()
    
    # Enable IPv6 forwarding
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
    sysctl -w net.ipv6.conf."$interface".forwarding=1 >/dev/null 2>&1
    
    for ipv6 in "${addresses[@]}"; do
        log_debug "Atanıyor: $ipv6"
        
        # Check if already assigned
        if ip -6 addr show dev "$interface" | grep -q "$ipv6"; then
            log_debug "$ipv6 zaten atanmış"
            ((success_count++))
            continue
        fi
        
        # Try to assign the address
        if ip -6 addr add "$ipv6/$Subnet_Mask" dev "$interface" 2>/dev/null; then
            # Verify assignment
            if ip -6 addr show dev "$interface" | grep -q "$ipv6"; then
                # Test basic connectivity
                if ip -6 route get "$ipv6" >/dev/null 2>&1; then
                    ((success_count++))
                    log_debug "✅ $ipv6 başarıyla atandı"
                else
                    log_debug "⚠️ $ipv6 atandı ama route problemi var"
                    failed_addresses+=("$ipv6:no_route")
                fi
            else
                log_debug "❌ $ipv6 ataması doğrulanamadı"
                failed_addresses+=("$ipv6:verify_failed")
            fi
        else
            log_debug "❌ $ipv6 atanamadı"
            failed_addresses+=("$ipv6:assign_failed")
        fi
        
        # Progress indicator for large batches
        if [[ $((success_count % 50)) -eq 0 ]] && [[ $success_count -gt 0 ]]; then
            log_info "İlerleme: $success_count/${#addresses[@]} adres atandı"
        fi
    done
    
    # Report results
    log_success "IPv6 atama tamamlandı: $success_count/${#addresses[@]} başarılı"
    
    if [[ ${#failed_addresses[@]} -gt 0 ]] && [[ ${#failed_addresses[@]} -lt 10 ]]; then
        log_warn "Başarısız atamalar:"
        printf '%s\n' "${failed_addresses[@]}" | head -5
    fi
    
    if [[ $success_count -eq 0 ]]; then
        log_error "Hiçbir IPv6 adresi atanamadı! Ağ yapılandırmasını kontrol edin."
        exit 1
    fi
    
    # Update IPv6_Array to only include successful assignments
    local temp_array=()
    for ipv6 in "${addresses[@]}"; do
        if ip -6 addr show dev "$interface" | grep -q "$ipv6"; then
            temp_array+=("$ipv6")
        fi
    done
    IPv6_Array=("${temp_array[@]}")
    
    return $success_count
}

# Enhanced 3proxy configuration generation
create_3proxy_configuration() {
    local auth_type="$1"
    local proxy_type="$2"
    local log_enabled="$3"
    local username="${4:-}"
    local password="${5:-}"
    local allowed_ip="${6:-}"
    
    log_info "3proxy yapılandırması oluşturuluyor..."
    
    # Create necessary directories
    mkdir -p /etc/3proxy
    mkdir -p /var/log
    mkdir -p /var/run
    
    local config_file="/etc/3proxy/3proxy.cfg"
    
    # Generate optimized configuration
    cat > "$config_file" << EOF
# Universal IPv6 Proxy Configuration
# Generated by: $SCRIPT_NAME v$SCRIPT_VERSION
# Date: $(date)
# Interface: $Selected_Interface
# Subnet: /$Subnet_Mask ($Subnet_Type)
# Active IPs: ${#IPv6_Array[@]}

# Daemon settings
daemon
pidfile /var/run/3proxy.pid

# DNS settings (multiple for redundancy)
nserver 1.1.1.1
nserver 8.8.8.8
nserver 2606:4700:4700::1111
nserver 2001:4860:4860::8888

# Performance tuning
maxconn 1000
nscache 65536
timeouts 1 5 30 60 180 1800 15 60

# Security settings
setgid 65535
setuid 65535

# Network binding
internal 0.0.0.0
external ::

# Memory and performance
stacksize 8000
EOF

    # Add logging if enabled
    if [[ "$log_enabled" == "YES" ]]; then
        cat >> "$config_file" << EOF

# Logging configuration
log /var/log/3proxy.log D
rotate 30
EOF
    fi

    # Add authentication configuration
    cat >> "$config_file" << EOF

# Flush previous rules
flush

# Authentication setup
EOF

    if [[ "$auth_type" == "PASS" ]]; then
        cat >> "$config_file" << EOF
auth strong
users $username:CL:$password
allow $username
EOF
    else
        cat >> "$config_file" << EOF
auth iponly
allow * $allowed_ip
EOF
    fi

    # Add proxy configurations
    cat >> "$config_file" << EOF

# Proxy configurations
EOF

    local port=30000
    local active_proxies=0
    
    for ipv6 in "${IPv6_Array[@]}"; do
        ((port++))
        ((active_proxies++))
        
        if [[ "$proxy_type" == "SOCKS5" ]]; then
            echo "socks -6 -n -a -p$port -e[$ipv6]" >> "$config_file"
        else
            echo "proxy -6 -n -a -p$port -e[$ipv6]" >> "$config_file"
        fi
        
        # Add comment every 10 proxies for readability
        if [[ $((active_proxies % 10)) -eq 0 ]]; then
            echo "# --- Batch $((active_proxies / 10)) (Ports $((port-9))-$port) ---" >> "$config_file"
        fi
    done
    
    log_success "3proxy konfigürasyonu oluşturuldu: $active_proxies aktif proxy"
}

# Advanced systemd service setup
setup_systemd_service() {
    log_info "Systemd servisi yapılandırılıyor..."
    
    local service_file="/etc/systemd/system/3proxy.service"
    
    cat > "$service_file" << EOF
[Unit]
Description=3proxy High Performance Proxy Server
Documentation=$GITHUB_REPO
After=network-online.target
Wants=network-online.target
RequiresMountsFor=/var/log /var/run

[Service]
Type=forking
User=root
Group=root
PIDFile=/var/run/3proxy.pid
ExecStartPre=/usr/bin/test -f /etc/3proxy/3proxy.cfg
ExecStart=/usr/bin/3proxy /etc/3proxy/3proxy.cfg
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=/bin/kill -TERM \$MAINPID
TimeoutStartSec=30
TimeoutStopSec=30
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=255
KillMode=mixed
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log /var/run /etc/3proxy
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    # Reload and enable service
    systemctl daemon-reload
    systemctl enable 3proxy.service
    
    log_success "Systemd servisi yapılandırıldı ve etkinleştirildi"
}

# Service management with health checks
manage_3proxy_service() {
    log_info "3proxy servisi yönetiliyor..."
    
    # Stop existing service
    if systemctl is-active --quiet 3proxy; then
        log_info "Mevcut 3proxy servisi durduruluyor..."
        systemctl stop 3proxy
        sleep 3
    fi
    
    # Start service
    log_info "3proxy servisi başlatılıyor..."
    if systemctl start 3proxy; then
        sleep 5
        
        # Health check
        if systemctl is-active --quiet 3proxy; then
            log_success "3proxy servisi başarıyla başlatıldı"
            
            # Additional connectivity test
            local test_port=30001
            if netstat -tlnp 2>/dev/null | grep -q ":$test_port.*3proxy"; then
                log_success "Proxy portları dinleniyor (örnek: $test_port)"
            else
                log_warn "Proxy portları henüz aktif olmayabilir, birkaç saniye bekleyin"
            fi
        else
            log_error "3proxy servisi başlatılamadı!"
            systemctl status 3proxy --no-pager
            return 1
        fi
    else
        log_error "3proxy servisi başlatma komutu başarısız!"
        return 1
    fi
}

# Comprehensive system validation
validate_system() {
    log_info "Sistem doğrulaması yapılıyor..."
    
    local validation_errors=()
    
    # Check root privileges
    if [[ "$(id -u)" -ne 0 ]]; then
        validation_errors+=("Root yetkisi gerekli")
    fi
    
    # Check IPv6 support
    if [[ ! -f /proc/net/if_inet6 ]]; then
        validation_errors+=("IPv6 desteği bulunamadı")
    fi
    
    # Check IPv6 forwarding capability
    if [[ ! -f /proc/sys/net/ipv6/conf/all/forwarding ]]; then
        validation_errors+=("IPv6 forwarding desteği yok")
    fi
    
    # Check basic networking tools
    local required_tools=("ip" "netstat" "ss")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            validation_errors+=("$tool komutu bulunamadı")
        fi
    done
    
    # Report validation results
    if [[ ${#validation_errors[@]} -gt 0 ]]; then
        log_error "Sistem doğrulama hataları:"
        printf '%s\n' "${validation_errors[@]}"
        exit 1
    fi
    
    log_success "Sistem doğrulaması başarılı"
}

# Interactive user interface
collect_user_preferences() {
    log_info "Kullanıcı tercihleri toplanıyor..."
    
    # Authentication type selection
    local auth_type
    auth_type=$(whiptail_menu "Kimlik Doğrulama" "Proxy kimlik doğrulama yöntemini seçin:" \
        "PASS" "Kullanıcı adı ve şifre ile kimlik doğrulama" \
        "IP" "IP tabanlı whitelist (şifresiz erişim)")
    
    # Proxy type selection
    local proxy_type
    proxy_type=$(whiptail_menu "Proxy Türü" "Kullanılacak proxy protokolünü seçin:" \
        "HTTP" "HTTP/HTTPS Proxy (Web tarayıcıları için ideal)" \
        "SOCKS5" "SOCKS5 Proxy (Tüm uygulamalar için evrensel)")
    
    # Logging preference
    local log_enabled
    log_enabled=$(whiptail_menu "Loglama" "Proxy erişim logları tutulsun mu?" \
        "YES" "Evet, tüm bağlantıları logla (/var/log/3proxy.log)" \
        "NO" "Hayır, log tutma (daha az disk kullanımı)")
    
    # Interface selection
    if [[ ${#Available_Interfaces[@]} -eq 1 ]]; then
        # Auto-select if only one interface
        local interface_info="${Available_Interfaces[0]}"
        Selected_Interface=$(echo "$interface_info" | cut -d: -f1)
        Selected_IPv6=$(echo "$interface_info" | cut -d: -f2)
        local subnet_mask=$(echo "$interface_info" | cut -d: -f3)
        classify_subnet "$subnet_mask" "$Selected_IPv6"
        log_info "Otomatik seçilen arayüz: $Selected_Interface ($Selected_IPv6/$subnet_mask)"
    else
        # Multiple interfaces available
        local if_menu_options=()
        for interface_info in "${Available_Interfaces[@]}"; do
            local iface=$(echo "$interface_info" | cut -d: -f1)
            local ipv6=$(echo "$interface_info" | cut -d: -f2)
            local subnet=$(echo "$interface_info" | cut -d: -f3)
            if_menu_options+=("$interface_info" "$iface: $ipv6/$subnet")
        done
        
        local selected_info
        selected_info=$(whiptail_menu "IPv6 Arayüzü" "Proxy için kullanılacak IPv6 arayüzünü seçin:" "${if_menu_options[@]}")
        
        Selected_Interface=$(echo "$selected_info" | cut -d: -f1)
        Selected_IPv6=$(echo "$selected_info" | cut -d: -f2)
        local subnet_mask=$(echo "$selected_info" | cut -d: -f3)
        classify_subnet "$subnet_mask" "$Selected_IPv6"
    fi
    
    # Proxy count with subnet-aware recommendations
    local max_recommended
    case "$Subnet_Type" in
        "tiny") max_recommended=10 ;;
        "small") max_recommended=100 ;;
        "medium") max_recommended=1000 ;;
        "large") max_recommended=5000 ;;
    esac
    
    local proxy_count
    proxy_count=$(whiptail_prompt "Kaç adet proxy oluşturulsun? (Önerilen max: $max_recommended)" "Proxy Sayısı" "100")
    
    # Validate proxy count
    if ! [[ "$proxy_count" =~ ^[0-9]+$ ]] || [[ $proxy_count -lt 1 ]]; then
        log_error "Geçersiz proxy sayısı: $proxy_count"
        exit 1
    fi
    
    if [[ $proxy_count -gt $max_recommended ]]; then
        log_warn "Girilen sayı önerilen maksimumdan fazla ($max_recommended)"
        if ! whiptail --title "Uyarı" --yesno "Devam etmek istediğinizden emin misiniz?" 10 60; then
            exit 1
        fi
    fi
    
    # Authentication credentials
    local username="" password="" allowed_ip=""
    if [[ "$auth_type" == "PASS" ]]; then
        username=$(whiptail_prompt "Proxy kullanıcı adını girin:" "Kimlik Doğrulama")
        password=$(whiptail_prompt "Proxy şifresini girin:" "Kimlik Doğrulama")
        
        # Validate credentials
        if [[ ${#username} -lt 3 ]] || [[ ${#password} -lt 6 ]]; then
            log_error "Kullanıcı adı en az 3, şifre en az 6 karakter olmalı"
            exit 1
        fi
    else
        allowed_ip=$(whiptail_prompt "Erişime izin verilecek IP adresini girin:" "IP Whitelist" "$(curl -s ifconfig.me || echo '1.2.3.4')")
        
        # Basic IP validation
        if ! [[ "$allowed_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            log_error "Geçersiz IP adresi formatı: $allowed_ip"
            exit 1
        fi
    fi
    
    # Store preferences globally
    USER_AUTH_TYPE="$auth_type"
    USER_PROXY_TYPE="$proxy_type"
    USER_LOG_ENABLED="$log_enabled"
    USER_PROXY_COUNT="$proxy_count"
    USER_USERNAME="$username"
    USER_PASSWORD="$password"
    USER_ALLOWED_IP="$allowed_ip"
    
    log_success "Kullanıcı tercihleri toplandı"
}

# Generate comprehensive status report
generate_status_report() {
    log_info "Durum raporu oluşturuluyor..."
    
    local report_file="/tmp/3proxy_setup_report.txt"
    
    cat > "$report_file" << EOF
============================================================
       UNIVERSAL IPv6 PROXY SETUP REPORT
============================================================

Setup Information:
- Script Version: $SCRIPT_VERSION
- Date: $(date)
- OS: $OS_TYPE $OS_VERSION
- Package Manager: $PACKAGE_MANAGER

Network Configuration:
- Selected Interface: $Selected_Interface
- Base IPv6: $Selected_IPv6
- Subnet: /$Subnet_Mask ($Subnet_Type)
- Total IPv6 Addresses: ${#IPv6_Array[@]}

Proxy Configuration:
- Type: $USER_PROXY_TYPE
- Authentication: $USER_AUTH_TYPE
- Logging: $USER_LOG_ENABLED
- Port Range: 30001-$((30000 + ${#IPv6_Array[@]}))

EOF

    if [[ "$USER_AUTH_TYPE" == "PASS" ]]; then
        cat >> "$report_file" << EOF
Authentication Details:
- Username: $USER_USERNAME
- Password: $USER_PASSWORD

EOF
    else
        cat >> "$report_file" << EOF
Access Control:
- Allowed IP: $USER_ALLOWED_IP

EOF
    fi

    cat >> "$report_file" << EOF
Service Information:
- Status: $(systemctl is-active 3proxy)
- Enabled: $(systemctl is-enabled 3proxy)
- Config: /etc/3proxy/3proxy.cfg
- Logs: /var/log/3proxy.log

Proxy List (First 10):
EOF

    local port=30000
    local count=0
    for ipv6 in "${IPv6_Array[@]}"; do
        ((port++))
        ((count++))
        echo "  Port $port -> [$ipv6]" >> "$report_file"
        [[ $count -ge 10 ]] && break
    done
    
    if [[ ${#IPv6_Array[@]} -gt 10 ]]; then
        echo "  ... and $((${#IPv6_Array[@]} - 10)) more proxies" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

Management Commands:
- Check Status: systemctl status 3proxy
- Restart Service: systemctl restart 3proxy
- View Logs: tail -f /var/log/3proxy.log
- Test Connectivity: curl --proxy localhost:30001 https://httpbin.org/ip

Connection Examples:
EOF

    if [[ "$USER_PROXY_TYPE" == "SOCKS5" ]]; then
        cat >> "$report_file" << EOF
- cURL: curl --socks5 localhost:30001 https://httpbin.org/ip
- Browser: SOCKS5 proxy localhost:30001
EOF
    else
        cat >> "$report_file" << EOF
- cURL: curl --proxy localhost:30001 https://httpbin.org/ip
- Browser: HTTP proxy localhost:30001
EOF
    fi

    cat >> "$report_file" << EOF

Troubleshooting:
- IPv6 Status: ip -6 addr show $Selected_Interface
- Port Status: netstat -tlnp | grep 3proxy
- Service Logs: journalctl -u 3proxy -f

============================================================
Repository: $GITHUB_REPO
============================================================
EOF

    # Display report
    echo ""
    log_success "🎉 KURULUM TAMAMLANDI! 🎉"
    echo ""
    cat "$report_file"
    echo ""
    log_info "Detaylı rapor: $report_file"
}

# Performance optimization
optimize_system() {
    log_info "Sistem performansı optimize ediliyor..."
    
    # Network optimizations
    cat > /etc/sysctl.d/99-3proxy-ipv6.conf << EOF
# IPv6 and network optimizations for 3proxy
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr
EOF

    # Apply optimizations
    sysctl -p /etc/sysctl.d/99-3proxy-ipv6.conf >/dev/null 2>&1
    
    # Firewall considerations (informational)
    if command -v ufw >/dev/null 2>&1; then
        log_info "UFW tespit edildi. Gerekirse portları manuel açın: ufw allow 30001:$((30000 + ${#IPv6_Array[@]}))/tcp"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        log_info "FirewallD tespit edildi. Gerekirse portları manuel açın"
    fi
    
    log_success "Sistem optimizasyonu tamamlandı"
}

# Global variable declarations
declare -g USER_AUTH_TYPE=""
declare -g USER_PROXY_TYPE=""
declare -g USER_LOG_ENABLED=""
declare -g USER_PROXY_COUNT=""
declare -g USER_USERNAME=""
declare -g USER_PASSWORD=""
declare -g USER_ALLOWED_IP=""

# Main execution function
main() {
    # Show banner
    show_banner
    
    # System validation
    validate_system
    
    # First-time installation check
    if [[ ! -f /ipv6lw_universal ]]; then
        log_info "İlk kurulum tespit edildi..."
        detect_operating_system
        install_system_packages
        install_3proxy
        touch /ipv6lw_universal
        log_success "Sistem kurulumu tamamlandı"
    else
        log_info "Mevcut kurulum tespit edildi, güncelleme kontrol ediliyor..."
        if ! command -v 3proxy >/dev/null 2>&1; then
            log_warn "3proxy bulunamadı, yeniden kuruluyor..."
            detect_operating_system
            install_3proxy
        fi
    fi
    
    # Network analysis
    analyze_ipv6_network
    
    # User input collection
    collect_user_preferences
    
    # IPv6 address generation
    generate_ipv6_addresses "$Selected_IPv6" "$USER_PROXY_COUNT" "$Selected_Interface"
    
    # IPv6 address assignment
    assign_ipv6_addresses "$Selected_Interface" "${IPv6_Array[@]}"
    
    # 3proxy configuration
    create_3proxy_configuration "$USER_AUTH_TYPE" "$USER_PROXY_TYPE" "$USER_LOG_ENABLED" \
                                "$USER_USERNAME" "$USER_PASSWORD" "$USER_ALLOWED_IP"
    
    # Systemd service setup
    setup_systemd_service
    
    # System optimization
    optimize_system
    
    # Service management
    manage_3proxy_service
    
    # Generate and display final report
    generate_status_report
    
    log_success "Universal IPv6 Proxy kurulumu başarıyla tamamlandı!"
}

# Error handling and cleanup
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script beklenmedik bir hatayla sonlandı (exit code: $exit_code)"
        echo "Destek için: $GITHUB_REPO/issues"
    fi
}

# Set up error handling
trap cleanup EXIT

# Enable debug mode if requested
if [[ "${1:-}" == "--debug" ]] || [[ "${DEBUG:-0}" == "1" ]]; then
    set -x
    export DEBUG=1
    log_info "Debug modu etkinleştirildi"
fi

# Version check
if [[ "${1:-}" == "--version" ]] || [[ "${1:-}" == "-v" ]]; then
    echo "$SCRIPT_NAME v$SCRIPT_VERSION"
    echo "Repository: $GITHUB_REPO"
    exit 0
fi

# Help information
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    show_banner
    echo "Kullanım: $0 [OPTIONS]"
    echo ""
    echo "Seçenekler:"
    echo "  --help, -h      Bu yardım mesajını göster"
    echo "  --version, -v   Sürüm bilgisini göster"
    echo "  --debug         Debug modu ile çalıştır"
    echo ""
    echo "Desteklenen Sistemler:"
    echo "  • Ubuntu 18.04+ / Debian 9+"
    echo "  • CentOS 7+ / RHEL 7+ / Fedora"
    echo "  • openSUSE / SLES"
    echo "  • Arch Linux"
    echo ""
    echo "Desteklenen Hosting Sağlayıcıları:"
    echo "  • Hetzner (IPv6 /64)"
    echo "  • OVH (IPv6 /128)"
    echo "  • DigitalOcean (IPv6 /120)"
    echo "  • Vultr (IPv6 /96)"
    echo "  • Linode (IPv6 /116)"
    echo "  • Ve diğer tüm IPv6 destekli sağlayıcılar"
    echo ""
    echo "Daha fazla bilgi: $GITHUB_REPO"
    exit 0
fi

# Execute main function
main "$@"
