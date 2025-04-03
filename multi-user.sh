#!/bin/bash
# =========================================
# 描述: 这个脚本用于管理 Snell 代理的多用户配置
# =========================================

# 定义颜色代码
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

# 定义配置目录和日志文件
SNELL_CONF_DIR="/etc/snell"
SNELL_CONF_FILE="${SNELL_CONF_DIR}/users/snell-main.conf"
LOG_FILE="/var/log/snell_manager.log"
INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

# 日志记录函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# 检查是否以 root 权限运行
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}请以 root 权限运行此脚本${RESET}"
        exit 1
    fi
}

# 检查 Snell 是否已安装
check_snell_installed() {
    if ! command -v snell-server &> /dev/null; then
        echo -e "${RED}未检测到 Snell 安装，请先安装 Snell${RESET}"
        exit 1
    fi
}

# 获取配置值
get_config_value() {
    local file=$1
    local key=$2
    awk -F'=' "/^${key}/ {print \$2}" "$file" | tr -d ' '
}

# 获取系统DNS
get_system_dns() {
    if [ -f "/etc/resolv.conf" ]; then
        local dns=$(grep -E '^nameserver' /etc/resolv.conf | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
        [ -n "$dns" ] && echo "$dns" && return 0
    fi
    echo "1.1.1.1,8.8.8.8"
}

# 获取用户输入的 DNS 服务器
get_dns() {
    read -rp "请输入 DNS 服务器地址 (直接回车使用系统DNS): " custom_dns
    if [ -z "$custom_dns" ]; then
        DNS=$(get_system_dns)
        echo -e "${GREEN}使用系统 DNS 服务器: $DNS${RESET}"
    else
        DNS=$custom_dns
        echo -e "${GREEN}使用自定义 DNS 服务器: $DNS${RESET}"
    fi
}

# 开放端口
open_port() {
    local port=$1
    if command -v ufw &> /dev/null; then
        echo -e "${CYAN}在 UFW 中开放端口 $port${RESET}"
        ufw allow "$port"/tcp >/dev/null 2>&1 || echo -e "${YELLOW}UFW 配置失败${RESET}"
    fi
    if command -v iptables &> /dev/null; then
        echo -e "${CYAN}在 iptables 中开放端口 $port${RESET}"
        iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
}

# 检查端口是否被占用
check_port_usage() {
    local port=$1
    local used_ports=$(get_all_ports)
    [[ "$used_ports" =~ (^|[[:space:]])"$port"($|[[:space:]]) ]] && return 1
    return 0
}

# 获取所有用户端口
get_all_ports() {
    [ ! -d "${SNELL_CONF_DIR}/users" ] && return 1
    for conf_file in "${SNELL_CONF_DIR}/users"/snell-*.conf; do
        [ -f "$conf_file" ] && awk -F: '/^listen/ {print $NF}' "$conf_file"
    done | sort -n | uniq
}

# 列出所有用户
list_users() {
    echo -e "\n${YELLOW}=== 当前用户列表 ===${RESET}"
    local count=0
    [ ! -d "${SNELL_CONF_DIR}/users" ] && echo -e "${YELLOW}当前没有配置的用户${RESET}" && return
    for user_conf in "${SNELL_CONF_DIR}/users"/*; do
        if [ -f "$user_conf" ]; then
            count=$((count + 1))
            local port=$(awk -F: '/^listen/ {print $NF}' "$user_conf")
            local psk=$(get_config_value "$user_conf" "psk")
            printf "${GREEN}用户 %-2d${RESET}:\n" "$count"
            printf "  ${YELLOW}%-10s${RESET}: %s\n" "端口" "$port"
            printf "  ${YELLOW}%-10s${RESET}: %s\n" "PSK" "$psk"
            printf "  ${YELLOW}%-10s${RESET}: %s\n" "配置文件" "$user_conf"
            echo
        fi
    done
    [ "$count" -eq 0 ] && echo -e "${YELLOW}当前没有配置的用户${RESET}"
}

# 添加新用户
add_user() {
    echo -e "\n${YELLOW}=== 添加新用户 ===${RESET}"
    mkdir -p "${SNELL_CONF_DIR}/users" || { echo -e "${RED}无法创建目录${RESET}"; exit 1; }
    
    while true; do
        read -rp "请输入新用户端口号 (1-65535): " PORT
        if [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; then
            if ! check_port_usage "$PORT"; then
                echo -e "${RED}端口 $PORT 已被使用${RESET}"
                continue
            fi
            break
        else
            echo -e "${RED}无效端口号${RESET}"
        fi
    done
    
    PSK=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)
    get_dns
    
    local user_conf="${SNELL_CONF_DIR}/users/snell-${PORT}.conf"
    cat > "$user_conf" << EOF || { echo -e "${RED}无法写入配置文件${RESET}"; exit 1; }
[snell-server]
listen = ::0:${PORT}
psk = ${PSK}
ipv6 = true
dns = ${DNS}
EOF
    chmod 600 "$user_conf"
    
    local service_name="snell-${PORT}"
    local service_file="${SYSTEMD_DIR}/${service_name}.service"
    cat > "$service_file" << EOF || { echo -e "${RED}无法写入服务文件${RESET}"; exit 1; }
[Unit]
Description=Snell Proxy Service (Port ${PORT})
After=network.target

[Service]
Type=simple
User=snell
Group=snell
LimitNOFILE=32768
ExecStart=${INSTALL_DIR}/snell-server -c ${user_conf}
AmbientCapabilities=CAP_NET_BIND_SERVICE
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=snell-server-${PORT}

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "$service_name" >/dev/null 2>&1
    systemctl start "$service_name" && systemctl is-active --quiet "$service_name" || { echo -e "${RED}服务启动失败${RESET}"; exit 1; }
    open_port "$PORT"
    
    log "添加新用户: 端口 $PORT"
    echo -e "\n${GREEN}用户添加成功！配置信息：${RESET}"
    printf "${CYAN}%-20s${RESET}\n" "------------------------"
    printf "${YELLOW}%-10s${RESET}: %s\n" "端口" "$PORT"
    printf "${YELLOW}%-10s${RESET}: %s\n" "PSK" "$PSK"
    printf "${YELLOW}%-10s${RESET}: %s\n" "配置文件" "$user_conf"
    printf "${CYAN}%-20s${RESET}\n" "------------------------"
}

# 删除用户
delete_user() {
    echo -e "\n${YELLOW}=== 删除用户 ===${RESET}"
    list_users
    read -rp "请输入要删除的用户端口号: " del_port
    
    local user_conf="${SNELL_CONF_DIR}/users/snell-${del_port}.conf"
    local service_name="snell-${del_port}"
    
    if [ -f "$user_conf" ]; then
        read -rp "确定删除端口 ${del_port} 的用户吗？(y/N): " confirm
        [[ "$confirm" != "y" && "$confirm" != "Y" ]] && echo -e "${YELLOW}操作已取消${RESET}" && return
        
        systemctl stop "$service_name" >/dev/null 2>&1
        systemctl disable "$service_name" >/dev/null 2>&1
        rm -f "${SYSTEMD_DIR}/${service_name}.service" "/lib/systemd/system/${service_name}.service" "$user_conf"
        systemctl daemon-reload
        
        log "删除用户: 端口 $del_port"
        echo -e "${GREEN}用户已成功删除${RESET}"
    else
        echo -e "${RED}未找到端口为 ${del_port} 的用户${RESET}"
    fi
}

# 修改用户配置
modify_user() {
    echo -e "\n${YELLOW}=== 修改用户配置 ===${RESET}"
    list_users
    read -rp "请输入要修改的用户端口号: " mod_port
    
    local user_conf="${SNELL_CONF_DIR}/users/snell-${mod_port}.conf"
    local service_name="snell-${mod_port}"
    
    if [ -f "$user_conf" ]; then
        echo -e "\n${YELLOW}请选择要修改的项目：${RESET}"
        printf "${GREEN}%-2s${RESET} 修改端口\n" "1."
        printf "${GREEN}%-2s${RESET} 重置 PSK\n" "2."
        printf "${GREEN}%-2s${RESET} 修改 DNS\n" "3."
        printf "${GREEN}%-2s${RESET} 返回\n" "0."
        read -rp "请输入选项 [0-3]: " mod_choice
        
        case "$mod_choice" in
            1)
                while true; do
                    read -rp "请输入新端口号 (1-65535): " new_port
                    if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1 ] && [ "$new_port" -le 65535 ]; then
                        if ! check_port_usage "$new_port"; then
                            echo -e "${RED}端口 $new_port 已被使用${RESET}"
                            continue
                        fi
                        break
                    else
                        echo -e "${RED}无效端口号${RESET}"
                    fi
                done
                
                systemctl stop "$service_name"
                sed -i "s/listen = ::0:${mod_port}/listen = ::0:${new_port}/" "$user_conf"
                mv "$user_conf" "${SNELL_CONF_DIR}/users/snell-${new_port}.conf"
                mv "${SYSTEMD_DIR}/${service_name}.service" "${SYSTEMD_DIR}/snell-${new_port}.service"
                sed -i "s/Port ${mod_port}/Port ${new_port}/;s/snell-server-${mod_port}/snell-server-${new_port}/;s|$user_conf|${SNELL_CONF_DIR}/users/snell-${new_port}.conf|" "${SYSTEMD_DIR}/snell-${new_port}.service"
                
                systemctl daemon-reload
                systemctl enable "snell-${new_port}" >/dev/null 2>&1
                systemctl start "snell-${new_port}" || { echo -e "${RED}服务启动失败${RESET}"; exit 1; }
                open_port "$new_port"
                
                log "修改用户端口: $mod_port -> $new_port"
                echo -e "${GREEN}端口修改成功${RESET}"
                ;;
            2)
                local new_psk=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)
                sed -i "s/psk = .*/psk = ${new_psk}/" "$user_conf"
                systemctl restart "$service_name"
                log "重置用户 PSK: 端口 $mod_port"
                echo -e "${GREEN}PSK 已重置为: ${new_psk}${RESET}"
                ;;
            3)
                get_dns
                sed -i "s/dns = .*/dns = ${DNS}/" "$user_conf"
                systemctl restart "$service_name"
                log "修改用户 DNS: 端口 $mod_port"
                echo -e "${GREEN}DNS 修改成功${RESET}"
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}无效选项${RESET}"
                ;;
        esac
    else
        echo -e "${RED}未找到端口为 ${mod_port} 的用户${RESET}"
    fi
}

# 显示用户配置信息
show_user_config() {
    echo -e "\n${YELLOW}=== 用户配置信息 ===${RESET}"
    list_users
    read -rp "请输入要查看的用户端口号: " view_port
    
    local user_conf="${SNELL_CONF_DIR}/users/snell-${view_port}.conf"
    if [ -f "$user_conf" ]; then
        local port=$(awk -F: '/^listen/ {print $NF}' "$user_conf")
        local psk=$(get_config_value "$user_conf" "psk")
        local dns=$(get_config_value "$user_conf" "dns")
        
        echo -e "\n${GREEN}用户配置详情：${RESET}"
        printf "${CYAN}%-20s${RESET}\n" "------------------------"
        printf "${YELLOW}%-10s${RESET}: %s\n" "端口" "$port"
        printf "${YELLOW}%-10s${RESET}: %s\n" "PSK" "$psk"
        printf "${YELLOW}%-10s${RESET}: %s\n" "DNS" "$dns"
        
        local cache_file="/tmp/snell_ip_cache"
        if [ ! -f "$cache_file" ] || [ $(find "$cache_file" -mmin +60 2>/dev/null) ]; then
            IPV4_ADDR=$(curl -s4 --max-time 5 https://api.ipify.org)
            IPV6_ADDR=$(curl -s6 --max-time 5 https://api64.ipify.org)
            echo "IPV4=$IPV4_ADDR" > "$cache_file"
            echo "IPV6=$IPV6_ADDR" >> "$cache_file"
        else
            source "$cache_file"
        fi
        
        if [ -n "$IPV4_ADDR" ]; then
            IP_COUNTRY_IPV4=$(curl -s --max-time 5 http://ipinfo.io/${IPV4_ADDR}/country 2>/dev/null || echo "未知")
            echo -e "\n${GREEN}IPv4 配置：${RESET}"
            echo -e "${GREEN}${IP_COUNTRY_IPV4} = snell, ${IPV4_ADDR}, ${port}, psk = ${psk}, version = 4, reuse = true, tfo = true${RESET}"
        fi
        
        if [ -n "$IPV6_ADDR" ]; then
            IP_COUNTRY_IPV6=$(curl -s --max-time 5 https://ipapi.co/${IPV6_ADDR}/country/ 2>/dev/null || echo "未知")
            echo -e "\n${GREEN}IPv6 配置：${RESET}"
            echo -e "${GREEN}${IP_COUNTRY_IPV6} = snell, ${IPV6_ADDR}, ${port}, psk = ${psk}, version = 4, reuse = true, tfo = true${RESET}"
        fi
        
        printf "${CYAN}%-20s${RESET}\n" "------------------------"
    else
        echo -e "${RED}未找到端口为 ${view_port} 的用户${RESET}"
    fi
}

# 主菜单
show_menu() {
    clear
    echo -e "${CYAN}============================================${RESET}"
    echo -e "${CYAN}          Snell 多用户管理${RESET}"
    echo -e "${CYAN}============================================${RESET}"
    echo -e "${GREEN}作者: jinqians${RESET}"
    echo -e "${GREEN}网站: https://jinqians.com${RESET}"
    echo -e "${GREEN}版本: 1.0.0${RESET}"
    echo -e "${CYAN}============================================${RESET}"
    
    echo -e "${YELLOW}=== 用户管理 ===${RESET}"
    printf "${GREEN}%-2s${RESET} 查看所有用户\n" "1."
    printf "${GREEN}%-2s${RESET} 添加新用户\n" "2."
    printf "${GREEN}%-2s${RESET} 删除用户\n" "3."
    printf "${GREEN}%-2s${RESET} 修改用户配置\n" "4."
    printf "${GREEN}%-2s${RESET} 查看用户详细配置\n" "5."
    printf "${GREEN}%-2s${RESET} 退出脚本\n" "0."
    echo -e "${CYAN}============================================${RESET}"
    read -rp "请输入选项 [0-5]: " choice
}

# 创建 Snell 用户（如果不存在）
setup_snell_user() {
    if ! id snell >/dev/null 2>&1; then
        useradd -r -s /sbin/nologin snell || { echo -e "${RED}无法创建 snell 用户${RESET}"; exit 1; }
    fi
}

# 初始检查
check_root
check_snell_installed
setup_snell_user
touch "$LOG_FILE" && chmod 644 "$LOG_FILE"

# 主循环
while true; do
    show_menu
    case "$choice" in
        1) list_users ;;
        2) add_user ;;
        3) delete_user ;;
        4) modify_user ;;
        5) show_user_config ;;
        0) echo -e "${GREEN}感谢使用，再见！${RESET}"; exit 0 ;;
        *) echo -e "${RED}请输入正确的选项 [0-5]${RESET}" ;;
    esac
    echo -e "\n${CYAN}按任意键返回主菜单...${RESET}"
    read -n 1 -s -r
done
