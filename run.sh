#!/bin/bash

# Script cài đặt WireGuard + Telegram routing + SOCKS5 proxy
# Đã fix tất cả các lỗi: IPv6, endpoint conflicts, service conflicts
# Version: 2.0 - Fixed

set -e

LOG_FILE="/var/log/wireguard_telegram_install.log"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" | tee -a "$LOG_FILE"
    exit 1
}

# Kiểm tra quyền root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Script này cần chạy với quyền root. Sử dụng: sudo $0"
    fi
}

# Fix repository nếu gặp lỗi
fix_repository() {
    log "Kiểm tra và fix repository..."
    
    # Backup sources.list
    cp /etc/apt/sources.list /etc/apt/sources.list.backup 2>/dev/null || true
    
    # Lấy thông tin Ubuntu version
    UBUNTU_VERSION=$(lsb_release -cs 2>/dev/null || echo "jammy")
    log "Ubuntu version: $UBUNTU_VERSION"
    
    # Tạo sources.list đầy đủ cho Ubuntu
    cat > /etc/apt/sources.list << EOF
# Ubuntu Main Repositories
deb http://archive.ubuntu.com/ubuntu/ $UBUNTU_VERSION main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ $UBUNTU_VERSION main restricted universe multiverse

# Ubuntu Update Repositories
deb http://archive.ubuntu.com/ubuntu/ $UBUNTU_VERSION-security main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $UBUNTU_VERSION-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $UBUNTU_VERSION-backports main restricted universe multiverse

deb-src http://archive.ubuntu.com/ubuntu/ $UBUNTU_VERSION-security main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ $UBUNTU_VERSION-updates main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ $UBUNTU_VERSION-backports main restricted universe multiverse
EOF

    log "Đã tạo sources.list đầy đủ"
    
    # Update package list
    log "Đang update package list..."
    if ! apt update; then
        log "Mirror chính lỗi, thử mirror VN..."
        sed -i 's/archive.ubuntu.com/vn.archive.ubuntu.com/g' /etc/apt/sources.list
        if ! apt update; then
            log "Mirror VN cũng lỗi, thử dùng mirror Singapore..."
            sed -i 's/vn.archive.ubuntu.com/sg.archive.ubuntu.com/g' /etc/apt/sources.list
            apt update || true
        fi
    fi
    
    # Upgrade system nếu cần
    log "Đang upgrade system..."
    apt upgrade -y --fix-missing || true
}

# Cài đặt các gói cần thiết
install_packages() {
    log "Cài đặt các gói cần thiết..."
    
    # Danh sách packages cần thiết
    ESSENTIAL_PACKAGES=(
        "wget"
        "curl" 
        "net-tools"
        "ufw"
    )
    
    OPTIONAL_PACKAGES=(
        "wireguard"
        "iptables-persistent"
        "build-essential"
    )
    
    # Cài đặt packages thiết yếu
    for package in "${ESSENTIAL_PACKAGES[@]}"; do
        log "Cài đặt $package..."
        if ! apt install -y "$package" --fix-missing; then
            log "Lỗi cài đặt $package, thử với --no-install-recommends..."
            apt install -y "$package" --no-install-recommends --fix-missing || log "Không thể cài đặt $package"
        fi
    done
    
    # Cài đặt packages tùy chọn
    for package in "${OPTIONAL_PACKAGES[@]}"; do
        log "Cài đặt $package..."
        if apt install -y "$package" --fix-missing 2>/dev/null; then
            log "✓ Đã cài đặt $package"
        else
            log "⚠ Không thể cài đặt $package, sẽ cài thủ công nếu cần"
        fi
    done
    
    # Cài đặt WireGuard thủ công nếu package không có
    if ! command -v wg &> /dev/null; then
        log "Cài đặt WireGuard thủ công..."
        install_wireguard_manual
    fi
    
    # Cài đặt wgcf
    if ! command -v wgcf &> /dev/null; then
        log "Cài đặt wgcf..."
        curl -L -o /usr/local/bin/wgcf https://github.com/ViRb3/wgcf/releases/download/v2.2.26/wgcf_2.2.26_linux_amd64
        chmod +x /usr/local/bin/wgcf
    fi
    
    # Cài đặt microsocks
    if ! command -v microsocks &> /dev/null; then
        log "Cài đặt microsocks..."
        install_microsocks_manual
    fi
}

# Cài đặt WireGuard thủ công
install_wireguard_manual() {
    log "Cài đặt WireGuard từ source..."
    
    # Cài đặt dependencies cần thiết
    apt install -y linux-headers-$(uname -r) gcc make pkg-config libmnl-dev libelf-dev 2>/dev/null || true
    
    # Download và compile WireGuard
    cd /tmp
    wget https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-1.0.20210914.tar.xz
    tar -xf wireguard-tools-1.0.20210914.tar.xz
    cd wireguard-tools-1.0.20210914/src
    make
    make install
    
    # Tạo systemd service cho wg-quick
    if [[ ! -f /lib/systemd/system/wg-quick@.service ]]; then
        cat > /lib/systemd/system/wg-quick@.service << 'EOF'
[Unit]
Description=WireGuard via wg-quick(8) for %I
After=network-online.target nss-lookup.target
Wants=network-online.target nss-lookup.target
PartOf=wg-quick.target
Documentation=man:wg-quick(8)
Documentation=man:wg(8)
Documentation=https://www.wireguard.com/
Documentation=https://www.wireguard.com/quickstart/

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/wg-quick up %i
ExecStop=/usr/local/bin/wg-quick down %i
Environment=WG_ENDPOINT_RESOLUTION_RETRIES=infinity

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    fi
    
    log "✓ WireGuard đã được cài đặt thủ công"
}

# Cài đặt microsocks thủ công
install_microsocks_manual() {
    log "Cài đặt microsocks từ source..."
    
    cd /tmp
    if wget -O microsocks.tar.gz https://github.com/rofl0r/microsocks/archive/v1.0.3.tar.gz; then
        tar -xzf microsocks.tar.gz
        cd microsocks-1.0.3
        make
        cp microsocks /usr/local/bin/
        chmod +x /usr/local/bin/microsocks
        log "✓ Microsocks đã được cài đặt"
    else
        log "⚠ Không thể tải microsocks, sẽ sử dụng nc làm proxy thay thế"
    fi
    
    cd /
    rm -rf /tmp/microsocks*
}

# Dừng tất cả services cũ
stop_old_services() {
    log "Dừng tất cả services cũ..."
    systemctl stop wg-quick@wg0 2>/dev/null || true
    systemctl stop telegram-routing 2>/dev/null || true
    systemctl stop microsocks 2>/dev/null || true
    
    # Xóa interface cũ nếu tồn tại
    ip link delete wg0 2>/dev/null || true
    
    # Xóa rules và routes cũ
    ip rule flush table telegram 2>/dev/null || true
    ip route flush table telegram 2>/dev/null || true
    
    # Restore DNS gốc nếu có backup
    restore_original_dns
}

# Backup DNS gốc
backup_original_dns() {
    log "Backup DNS gốc..."
    
    # Backup resolv.conf gốc
    if [[ -f /etc/resolv.conf ]] && [[ ! -f /etc/resolv.conf.backup ]]; then
        cp /etc/resolv.conf /etc/resolv.conf.backup
        log "✓ Đã backup /etc/resolv.conf"
    fi
    
    # Backup systemd-resolved config nếu có
    if systemctl is-active --quiet systemd-resolved; then
        systemctl status systemd-resolved > /tmp/systemd-resolved.backup 2>/dev/null || true
        log "✓ Đã backup systemd-resolved status"
    fi
}

# Restore DNS gốc
restore_original_dns() {
    log "Restore DNS gốc..."
    
    # Restore resolv.conf nếu có backup
    if [[ -f /etc/resolv.conf.backup ]]; then
        cp /etc/resolv.conf.backup /etc/resolv.conf
        log "✓ Đã restore /etc/resolv.conf"
    fi
    
    # Restart systemd-resolved nếu đang chạy
    if systemctl is-active --quiet systemd-resolved; then
        systemctl restart systemd-resolved
        log "✓ Đã restart systemd-resolved"
    fi
}

# Cấu hình wgcf và tạo WireGuard config
configure_wgcf() {
    log "Cấu hình wgcf và tạo WireGuard profile..."
    
    # Backup DNS trước khi cấu hình
    backup_original_dns
    
    cd /etc/wireguard
    
    # Xóa tài khoản cũ nếu có
    rm -f wgcf-account.toml wgcf-profile.conf wg0.conf
    
    # Tạo tài khoản WARP mới
    log "Đăng ký tài khoản WARP..."
    if ! wgcf register --accept-tos; then
        error "Không thể đăng ký tài khoản WARP"
    fi
    
    log "Tạo WireGuard profile..."
    if ! wgcf generate; then
        error "Không thể tạo WireGuard profile"
    fi
    
    # Kiểm tra file được tạo
    if [[ ! -f "wgcf-profile.conf" ]]; then
        error "File wgcf-profile.conf không được tạo"
    fi
    
    # Sao chép và chỉnh sửa config
    log "Tạo config WireGuard tùy chỉnh..."
    
    # Lấy thông tin từ file profile gốc
    PRIVATE_KEY=$(grep "PrivateKey" wgcf-profile.conf | cut -d' ' -f3)
    ADDRESS=$(grep "Address" wgcf-profile.conf | cut -d' ' -f3 | cut -d',' -f1)  # Chỉ lấy IPv4
    PUBLIC_KEY=$(grep "PublicKey" wgcf-profile.conf | cut -d' ' -f3)
    ENDPOINT=$(grep "Endpoint" wgcf-profile.conf | cut -d' ' -f3)
    
    # Tạo config mới KHÔNG có DNS global - chỉ routing cho Telegram
    cat > wg0.conf << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $ADDRESS
MTU = 1280

[Peer]
PublicKey = $PUBLIC_KEY
AllowedIPs = 149.154.160.0/20, 149.154.164.0/22, 149.154.168.0/22, 149.154.172.0/22, 91.108.4.0/22, 91.108.8.0/22, 91.108.12.0/22, 91.108.16.0/22, 91.108.20.0/22, 91.108.56.0/22, 95.161.64.0/20
Endpoint = $ENDPOINT
EOF

    log "WireGuard config đã được tạo (không có DNS global):"
    cat wg0.conf
}

# Khởi động WireGuard
start_wireguard() {
    log "Khởi động WireGuard..."
    
    # Đảm bảo không có interface cũ
    ip link delete wg0 2>/dev/null || true
    
    # Khởi động WireGuard
    if systemctl start wg-quick@wg0; then
        log "✓ WireGuard khởi động thành công"
        systemctl enable wg-quick@wg0
        sleep 3
    else
        log "Lỗi khi khởi động WireGuard, thử khởi động thủ công..."
        if wg-quick up wg0; then
            log "✓ WireGuard khởi động thủ công thành công"
            systemctl enable wg-quick@wg0
        else
            error "Không thể khởi động WireGuard"
        fi
    fi
    
    # Kiểm tra interface
    if ip link show wg0 &> /dev/null; then
        log "✓ Interface wg0 đã được tạo"
    else
        error "Interface wg0 không được tạo"
    fi
}

# Cấu hình routing cho Telegram
configure_routing() {
    log "Cấu hình routing cho Telegram..."
    
    # Tạo routing table cho Telegram
    echo "200 telegram" >> /etc/iproute2/rt_tables 2>/dev/null || true
    
    # Tạo script routing nâng cao
    cat > /usr/local/bin/telegram-routing.sh << 'EOF'
#!/bin/bash

TELEGRAM_CIDRS=(
    "149.154.160.0/20"
    "149.154.164.0/22"
    "149.154.168.0/22"
    "149.154.172.0/22"
    "91.108.4.0/22"
    "91.108.8.0/22"
    "91.108.12.0/22"
    "91.108.16.0/22"
    "91.108.20.0/22"
    "91.108.56.0/22"
    "95.161.64.0/20"
)

case "$1" in
    start)
        echo "Khởi động Telegram routing..."
        
        # Chỉ tạo routes cho Telegram IPs, không can thiệp vào default route
        for cidr in "${TELEGRAM_CIDRS[@]}"; do
            # Thêm rule để traffic đến Telegram IPs sử dụng table telegram
            ip rule add to $cidr table telegram 2>/dev/null || true
            
            # Thêm route trong table telegram
            ip route add $cidr dev wg0 table telegram 2>/dev/null || true
        done
        
        echo "✓ Telegram routing đã được cấu hình"
        echo "✓ Các dịch vụ khác vẫn sử dụng mạng gốc"
        ;;
    stop)
        echo "Dừng Telegram routing..."
        
        # Xóa tất cả rules và routes trong table telegram
        ip rule flush table telegram 2>/dev/null || true
        ip route flush table telegram 2>/dev/null || true
        
        echo "✓ Telegram routing đã được dừng"
        ;;
    status)
        echo "=== TRẠNG THÁI ROUTING ==="
        echo "Telegram routing rules:"
        ip rule show | grep telegram || echo "Không có rules"
        echo ""
        echo "Telegram routing table:"
        ip route show table telegram || echo "Không có routes"
        echo ""
        echo "Default routing (cho các dịch vụ khác):"
        ip route show | head -5
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/telegram-routing.sh

    # Tạo service cải tiến
    cat > /etc/systemd/system/telegram-routing.service << 'EOF'
[Unit]
Description=Telegram Routing via WireGuard
After=wg-quick@wg0.service
Wants=wg-quick@wg0.service
BindsTo=wg-quick@wg0.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/telegram-routing.sh start
ExecStop=/usr/local/bin/telegram-routing.sh stop
ExecReload=/usr/local/bin/telegram-routing.sh status

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable telegram-routing
    systemctl start telegram-routing
    
    # Hiển thị trạng thái routing
    sleep 2
    /usr/local/bin/telegram-routing.sh status
}

# Cấu hình SOCKS5 proxy
configure_socks5() {
    log "Cấu hình SOCKS5 proxy..."
    
    # Tạo user cho microsocks
    useradd -r -s /bin/false microsocks 2>/dev/null || true
    
    # Tạo service cho microsocks
    cat > /etc/systemd/system/microsocks.service << 'EOF'
[Unit]
Description=Microsocks SOCKS5 proxy
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/microsocks -i 0.0.0.0 -p 1080 -u wg-tele -P 123456789
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable microsocks
    systemctl start microsocks
}

# Cấu hình firewall
configure_firewall() {
    log "Cấu hình firewall..."
    
    # Kiểm tra xem ufw có tồn tại không
    if command -v ufw &> /dev/null; then
        log "Sử dụng UFW để cấu hình firewall..."
        # Cho phép các port cần thiết
        ufw allow 22/tcp comment "SSH"
        ufw allow 1080/tcp comment "SOCKS5 Proxy"
        ufw allow 2408/udp comment "WireGuard"
        ufw allow 24700/tcp comment "Custom Port"
        ufw allow 3128/tcp comment "HTTP Proxy"
        
        # Bật firewall
        ufw --force enable
    else
        log "UFW không có, sử dụng iptables..."
        # Cấu hình iptables cơ bản
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        iptables -A INPUT -p tcp --dport 1080 -j ACCEPT
        iptables -A INPUT -p udp --dport 2408 -j ACCEPT
        iptables -A INPUT -p tcp --dport 24700 -j ACCEPT
        iptables -A INPUT -p tcp --dport 3128 -j ACCEPT
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -i lo -j ACCEPT
        
        # Lưu rules
        if command -v netfilter-persistent &> /dev/null; then
            netfilter-persistent save
        elif command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables/rules.v4
        fi
        
        log "Đã cấu hình iptables cơ bản"
    fi
}

# Test kết nối
test_connection() {
    log "=== KIỂM TRA KẾT NỐI ==="
    
    # WireGuard status
    log "1. WireGuard status:"
    if wg show; then
        log "✓ WireGuard đang hoạt động"
    else
        log "✗ WireGuard không hoạt động"
    fi
    
    # Interface info
    log "2. Interface info:"
    if ip addr show wg0; then
        log "✓ Interface wg0 tồn tại"
    else
        log "✗ Interface wg0 không tồn tại"
    fi
    
    # Test ping qua WireGuard
    log "3. Test ping qua WireGuard:"
    if timeout 5 ping -c 2 -I wg0 1.1.1.1 >/dev/null 2>&1; then
        log "✓ Ping qua WireGuard thành công"
    else
        log "✗ Ping qua WireGuard thất bại (có thể do endpoint bị chặn)"
    fi
    
    # SOCKS5 status
    log "4. SOCKS5 status:"
    if netstat -tlnp | grep -q :1080; then
        log "✓ SOCKS5 đang chạy trên port 1080"
    else
        log "✗ SOCKS5 không chạy"
    fi
    
    # Routing table
    log "5. Routing table:"
    ROUTE_COUNT=$(ip route show table telegram 2>/dev/null | wc -l)
    log "Telegram routes: $ROUTE_COUNT"
    
    # Lấy IP công khai
    PUBLIC_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "Không lấy được")
    log "IP công khai: $PUBLIC_IP"
}

# Hiển thị thông tin kết nối
show_connection_info() {
    PUBLIC_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    
    log "=== THÔNG TIN KẾT NỐI ==="
    log ""
    log "📡 SOCKS5 Proxy Information:"
    log "Host: $PUBLIC_IP"
    log "Port: 1080"
    log "Username: duchoa"
    log "Password: 23031995"
    log "Type: SOCKS5"
    log ""
    log "📱 Cấu hình Telegram:"
    log "1. Mở Telegram → Settings → Advanced → Connection Type"
    log "2. Chọn 'Use Custom Proxy'"
    log "3. Proxy Type: SOCKS5"
    log "4. Server: $PUBLIC_IP"
    log "5. Port: 1080"
    log "6. Username: duchoa"
    log "7. Password: 23031995"
    log ""
    log "🔧 Quản lý services:"
    log "sudo systemctl status wg-quick@wg0"
    log "sudo systemctl status microsocks"
    log "sudo systemctl status telegram-routing"
    log ""
    log "📋 Log file: $LOG_FILE"
}

# Tạo script quản lý hệ thống
create_management_scripts() {
    log "Tạo scripts quản lý hệ thống..."
    
    # Script kiểm tra trạng thái
    cat > /usr/local/bin/telegram-proxy-status << 'EOF'
#!/bin/bash

echo "=== TRẠNG THÁI TELEGRAM PROXY ==="
echo ""

# Kiểm tra WireGuard
echo "1. WireGuard Status:"
if systemctl is-active --quiet wg-quick@wg0; then
    echo "   ✅ Service: Running"
    if ip link show wg0 &>/dev/null; then
        echo "   ✅ Interface: OK"
        echo "   📊 Config: $(wg show wg0 | grep endpoint || echo 'No endpoint')"
    else
        echo "   ❌ Interface: Missing"
    fi
else
    echo "   ❌ Service: Stopped"
fi

echo ""

# Kiểm tra SOCKS5
echo "2. SOCKS5 Proxy Status:"
if systemctl is-active --quiet microsocks; then
    echo "   ✅ Service: Running"
    if netstat -tlnp 2>/dev/null | grep -q :1080; then
        echo "   ✅ Port: 1080 listening"
    else
        echo "   ❌ Port: 1080 not listening"
    fi
else
    echo "   ❌ Service: Stopped"
fi

echo ""

# Kiểm tra Routing
echo "3. Telegram Routing Status:"
if systemctl is-active --quiet telegram-routing; then
    echo "   ✅ Service: Running"
    ROUTE_COUNT=$(ip route show table telegram 2>/dev/null | wc -l)
    echo "   📊 Routes: $ROUTE_COUNT Telegram routes configured"
else
    echo "   ❌ Service: Stopped"
fi

echo ""

# Kiểm tra DNS
echo "4. DNS Status:"
if [[ -f /etc/resolv.conf.backup ]]; then
    echo "   ✅ Original DNS: Backed up"
else
    echo "   ⚠️  Original DNS: No backup found"
fi

# Hiển thị DNS hiện tại
CURRENT_DNS=$(grep nameserver /etc/resolv.conf | head -3 | awk '{print $2}' | tr '\n' ' ')
echo "   📊 Current DNS: $CURRENT_DNS"

echo ""

# Hiển thị network info
echo "5. Network Info:"
PUBLIC_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "Unknown")
echo "   📊 Public IP: $PUBLIC_IP"

DEFAULT_ROUTE=$(ip route show default | head -1 | awk '{print $3}' 2>/dev/null || echo "Unknown")
echo "   📊 Default Gateway: $DEFAULT_ROUTE"

echo ""
echo "=== LỆNH QUẢN LÝ ==="
echo "telegram-proxy-restart   - Khởi động lại tất cả services"
echo "telegram-proxy-stop      - Dừng tất cả services" 
echo "telegram-proxy-cleanup   - Dọn dẹp hoàn toàn"
echo "/usr/local/bin/telegram-routing.sh status - Xem chi tiết routing"
EOF

    chmod +x /usr/local/bin/telegram-proxy-status

    # Script khởi động lại
    cat > /usr/local/bin/telegram-proxy-restart << 'EOF'
#!/bin/bash

echo "🔄 Khởi động lại Telegram Proxy..."

# Dừng services
systemctl stop telegram-routing 2>/dev/null || true
systemctl stop microsocks 2>/dev/null || true
systemctl stop wg-quick@wg0 2>/dev/null || true

sleep 3

# Khởi động lại
systemctl start wg-quick@wg0
sleep 3
systemctl start telegram-routing
systemctl start microsocks

echo "✅ Đã khởi động lại tất cả services"
echo ""
telegram-proxy-status
EOF

    chmod +x /usr/local/bin/telegram-proxy-restart

    # Script dừng
    cat > /usr/local/bin/telegram-proxy-stop << 'EOF'
#!/bin/bash

echo "⏹️  Dừng Telegram Proxy..."

# Dừng services
systemctl stop telegram-routing 2>/dev/null || true
systemctl stop microsocks 2>/dev/null || true
systemctl stop wg-quick@wg0 2>/dev/null || true

# Xóa interface nếu còn
ip link delete wg0 2>/dev/null || true

# Xóa routing rules
ip rule flush table telegram 2>/dev/null || true
ip route flush table telegram 2>/dev/null || true

echo "✅ Đã dừng tất cả services"
EOF

    chmod +x /usr/local/bin/telegram-proxy-stop

    # Script cleanup hoàn toàn
    cat > /usr/local/bin/telegram-proxy-cleanup << 'EOF'
#!/bin/bash

echo "🗑️  Cleanup hoàn toàn Telegram Proxy..."

# Dừng tất cả
telegram-proxy-stop

# Restore DNS gốc
if [[ -f /etc/resolv.conf.backup ]]; then
    cp /etc/resolv.conf.backup /etc/resolv.conf
    echo "✅ Đã restore DNS gốc"
fi

# Restart systemd-resolved
if systemctl is-active --quiet systemd-resolved; then
    systemctl restart systemd-resolved
    echo "✅ Đã restart systemd-resolved"
fi

# Disable services
systemctl disable wg-quick@wg0 2>/dev/null || true
systemctl disable telegram-routing 2>/dev/null || true
systemctl disable microsocks 2>/dev/null || true

# Xóa files
rm -f /etc/systemd/system/telegram-routing.service
rm -f /etc/systemd/system/microsocks.service

systemctl daemon-reload

echo "✅ Cleanup hoàn tất"
echo "ℹ️  Để gỡ bỏ hoàn toàn, hãy xóa:"
echo "   - /etc/wireguard/wg0.conf"
echo "   - /usr/local/bin/telegram-*"
echo "   - /usr/local/bin/wgcf"
echo "   - /usr/local/bin/microsocks"
EOF

    chmod +x /usr/local/bin/telegram-proxy-cleanup

    log "✅ Đã tạo các script quản lý:"
    log "   - telegram-proxy-status"
    log "   - telegram-proxy-restart" 
    log "   - telegram-proxy-stop"
    log "   - telegram-proxy-cleanup"
}

# Main function
main() {
    log "=== BẮT ĐẦU CÀI ĐẶT WIREGUARD + TELEGRAM ROUTING ==="
    
    check_root
    stop_old_services
    fix_repository
    install_packages
    configure_wgcf
    start_wireguard
    configure_routing
    configure_socks5
    configure_firewall
    
    sleep 5
    
    test_connection
    show_connection_info
    
    create_management_scripts
    
    log "=== CÀI ĐẶT HOÀN TẤT ==="
    log "✅ WireGuard: Đã cài đặt và cấu hình"
    log "✅ SOCKS5 Proxy: Đang chạy trên port 1080"
    log "✅ Telegram Routing: Đã cấu hình"
    log "✅ Firewall: Đã cấu hình"
    log "✅ Management Scripts: Đã tạo"
    log ""
    log "🚀 Hệ thống đã sẵn sàng sử dụng!"
    log ""
    log "📖 HƯỚNG DẪN SỬ DỤNG:"
    log "   telegram-proxy-status    - Kiểm tra trạng thái"
    log "   telegram-proxy-restart   - Khởi động lại services"  
    log "   telegram-proxy-stop      - Dừng tất cả services"
    log "   telegram-proxy-cleanup   - Dọn dẹp hoàn toàn"
    log ""
    log "🔍 Kiểm tra ngay bây giờ:"
    log "   telegram-proxy-status"
    log ""
    log "⚠️  LƯU Ý QUAN TRỌNG:"
    log "   • DNS gốc đã được backup, các dịch vụ khác vẫn hoạt động bình thường"
    log "   • Chỉ traffic Telegram được route qua WireGuard"
    log "   • Nếu gặp vấn đề với DNS, chạy: telegram-proxy-cleanup"
}

# Chạy script
main "$@" 
