#!/bin/bash
# =========================================
# 日期: 2025年3月
# 描述: 这个脚本用于安装、卸载、查看和更新 Snell 代理
# =========================================

# 定义颜色代码
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

# 当前版本号
current_version="1.0"

# 检查 bc 是否安装
check_bc() {
    if ! command -v bc &> /dev/null; then
        echo -e "${YELLOW}未检测到 bc，正在安装...${RESET}"
        if [ -x "$(command -v apt)" ]; then
            wait_for_apt
            apt update && apt install -y bc
        elif [ -x "$(command -v yum)" ]; then
            yum install -y bc
        else
            echo -e "${RED}未支持的包管理器，无法安装 bc。请手动安装 bc。${RESET}"
            exit 1
        fi
    fi
}

# 定义系统路径
INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
SNELL_CONF_DIR="/etc/snell"
SNELL_CONF_FILE="${SNELL_CONF_DIR}/snell-main.conf"
SYSTEMD_SERVICE_FILE="${SYSTEMD_DIR}/snell.service"

# 旧的配置文件路径（用于兼容性检查）
OLD_SNELL_CONF_FILE="${SNELL_CONF_DIR}/snell-server.conf"
OLD_SYSTEMD_SERVICE_FILE="/lib/systemd/system/snell.service"

# 检查并迁移旧配置
check_and_migrate_config() {
    local need_migration=false
    local old_files_exist=false

    if [ -f "$OLD_SNELL_CONF_FILE" ] || [ -f "$OLD_SYSTEMD_SERVICE_FILE" ]; then
        old_files_exist=true
        echo -e "\n${YELLOW}检测到旧版本的 Snell 配置文件${RESET}"
        echo -e "旧配置位置："
        [ -f "$OLD_SNELL_CONF_FILE" ] && echo -e "- 配置文件：${OLD_SNELL_CONF_FILE}"
        [ -f "$OLD_SYSTEMD_SERVICE_FILE" ] && echo -e "- 服务文件：${OLD_SYSTEMD_SERVICE_FILE}"

        if [ ! -d "${SNELL_CONF_DIR}" ]; then
            need_migration=true
            mkdir -p "${SNELL_CONF_DIR}"
            chown -R nobody:nogroup "${SNELL_CONF_DIR}"
            chmod -R 755 "${SNELL_CONF_DIR}"
        fi
    fi

    if [ "$old_files_exist" = true ]; then
        echo -e "\n${YELLOW}是否要迁移旧的配置文件？[y/N]${RESET}"
        read -r choice
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            echo -e "${CYAN}开始迁移配置文件...${RESET}"
            systemctl stop snell 2>/dev/null

            if [ -f "$OLD_SNELL_CONF_FILE" ]; then
                cp "$OLD_SNELL_CONF_FILE" "${SNELL_CONF_FILE}"
                chown nobody:nogroup "${SNELL_CONF_FILE}"
                chmod 644 "${SNELL_CONF_FILE}"
                echo -e "${GREEN}已迁移配置文件${RESET}"
            fi

            if [ -f "$OLD_SYSTEMD_SERVICE_FILE" ]; then
                sed -e "s|${OLD_SNELL_CONF_FILE}|${SNELL_CONF_FILE}|g" "$OLD_SYSTEMD_SERVICE_FILE" > "$SYSTEMD_SERVICE_FILE"
                chmod 644 "$SYSTEMD_SERVICE_FILE"
                echo -e "${GREEN}已迁移服务文件${RESET}"
            fi

            echo -e "${YELLOW}是否删除旧的配置文件？[y/N]${RESET}"
            read -r del_choice
            if [[ "$del_choice" == "y" || "$del_choice" == "Y" ]]; then
                [ -f "$OLD_SNELL_CONF_FILE" ] && rm -f "$OLD_SNELL_CONF_FILE"
                [ -f "$OLD_SYSTEMD_SERVICE_FILE" ] && rm -f "$OLD_SYSTEMD_SERVICE_FILE"
                echo -e "${GREEN}已删除旧的配置文件${RESET}"
            fi

            systemctl daemon-reload
            systemctl start snell

            if systemctl is-active --quiet snell; then
                echo -e "${GREEN}配置迁移完成，服务已成功启动${RESET}"
            else
                echo -e "${RED}警告：服务启动失败，请检查配置文件和权限${RESET}"
                systemctl status snell
            fi
        else
            echo -e "${YELLOW}跳过配置迁移${RESET}"
        fi
    fi
}

# 等待其他 apt 进程完成
wait_for_apt() {
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        echo -e "${YELLOW}等待其他 apt 进程完成...${RESET}"
        sleep 1
    done
}

# 检查是否以 root 权限运行
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}请以 root 权限运行此脚本.${RESET}"
        exit 1
    fi
}
check_root

# 检查 jq 是否安装
check_jq() {
    if ! command -v jq &> /dev/null; then
        echo -e "${YELLOW}未检测到 jq，正在安装...${RESET}"
        if [ -x "$(command -v apt)" ]; then
            wait_for_apt
            apt update && apt install -y jq
        elif [ -x "$(command -v yum)" ]; then
            yum install -y jq
        else
            echo -e "${RED}未支持的包管理器，无法安装 jq。请手动安装 jq。${RESET}"
            exit 1
        fi
    fi
}
check_jq

# 检查 Snell 是否已安装
check_snell_installed() {
    if command -v snell-server &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# 获取 Snell 最新版本
get_latest_snell_version() {
    latest_version=$(curl -s https://manual.nssurge.com/others/snell.html | grep -oP 'snell-server-v\K[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
    if [ -n "$latest_version" ]; then
        SNELL_VERSION="v${latest_version}"
    else
        echo -e "${RED}获取 Snell 最新版本失败，使用默认版本 ${SNELL_VERSION}${RESET}"
    fi
}

# 比较版本号
version_greater_equal() {
    local ver1=$1
    local ver2=$2

    ver1=$(echo "${ver1#[vV]}" | tr '[:upper:]' '[:lower:]')
    ver2=$(echo "${ver2#[vV]}" | tr '[:upper:]' '[:lower:]')

    IFS='.' read -ra VER1 <<< "$ver1"
    IFS='.' read -ra VER2 <<< "$ver2"

    while [ ${#VER1[@]} -lt 3 ]; do
        VER1+=("0")
    done
    while [ ${#VER2[@]} -lt 3 ]; do
        VER2+=("0")
    done

    for i in {0..2}; do
        if [ "${VER1[i]:-0}" -gt "${VER2[i]:-0}" ]; then
            return 0
        elif [ "${VER1[i]:-0}" -lt "${VER2[i]:-0}" ]; then
            return 1
        fi
    done
    return 0
}

# 用户输入端口号，默认 6160
get_user_port() {
    read -rp "请输入要使用的端口号 (默认 6160，直接回车使用默认值): " PORT
    if [ -z "$PORT" ]; then
        PORT=6160
        echo -e "${GREEN}使用默认端口: $PORT${RESET}"
    elif [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; then
        echo -e "${GREEN}已选择端口: $PORT${RESET}"
    else
        echo -e "${RED}无效端口号，使用默认端口 6160${RESET}"
        PORT=6160
    fi
}

# 获取用户输入的 DNS 服务器，默认 1.1.1.1,8.8.8.8
get_dns() {
    read -rp "请输入 DNS 服务器地址 (默认 1.1.1.1,8.8.8.8，直接回车使用默认值): " custom_dns
    if [ -z "$custom_dns" ]; then
        DNS="1.1.1.1,8.8.8.8"
        echo -e "${GREEN}使用默认 DNS 服务器: $DNS${RESET}"
    else
        DNS=$custom_dns
        echo -e "${GREEN}使用自定义 DNS 服务器: $DNS${RESET}"
    fi
}

# 开放端口 (ufw 和 iptables)
open_port() {
    local PORT=$1
    if command -v ufw &> /dev/null; then
        echo -e "${CYAN}在 UFW 中开放端口 $PORT${RESET}"
        ufw allow "$PORT"/tcp
    fi

    if command -v iptables &> /dev/null; then
        echo -e "${CYAN}在 iptables 中开放端口 $PORT${RESET}"
        iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT
        if [ ! -d "/etc/iptables" ]; then
            mkdir -p /etc/iptables
        fi
        iptables-save > /etc/iptables/rules.v4 || true
    fi
}

# 安装 Snell
install_snell() {
    echo -e "${CYAN}正在安装 Snell${RESET}"

    wait_for_apt
    apt update && apt install -y wget unzip

    get_latest_snell_version
    ARCH=$(uname -m)
    SNELL_URL=""

    if [[ ${ARCH} == "aarch64" ]]; then
        SNELL_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-aarch64.zip"
    else
        SNELL_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-amd64.zip"
    fi

    wget ${SNELL_URL} -O snell-server.zip
    if [ $? -ne 0 ]; then
        echo -e "${RED}下载 Snell 失败。${RESET}"
        exit 1
    fi

    unzip -o snell-server.zip -d ${INSTALL_DIR}
    if [ $? -ne 0 ]; then
        echo -e "${RED}解压缩 Snell 失败。${RESET}"
        exit 1
    fi

    rm snell-server.zip
    chmod +x ${INSTALL_DIR}/snell-server

    get_user_port
    get_dns
    PSK=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)

    mkdir -p ${SNELL_CONF_DIR}

    cat > ${SNELL_CONF_FILE} << EOF
[snell-server]
listen = ::0:${PORT}
psk = ${PSK}
ipv6 = true
dns = ${DNS}
EOF

    cat > ${SYSTEMD_SERVICE_FILE} << EOF
[Unit]
Description=Snell Proxy Service
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
LimitNOFILE=32768
ExecStart=${INSTALL_DIR}/snell-server -c ${SNELL_CONF_FILE}
AmbientCapabilities=CAP_NET_BIND_SERVICE
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=snell-server

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    if [ $? -ne 0 ]; then
        echo -e "${RED}重载 Systemd 配置失败。${RESET}"
        exit 1
    fi

    systemctl enable snell
    if [ $? -ne 0 ]; then
        echo -e "${RED}开机自启动 Snell 失败。${RESET}"
        exit 1
    fi

    systemctl start snell
    if [ $? -ne 0 ]; then
        echo -e "${RED}启动 Snell 服务失败。${RESET}"
        exit 1
    fi

    open_port "$PORT"

    echo -e "\n${GREEN}安装完成！以下是您的配置信息：${RESET}"
    echo -e "${CYAN}--------------------------------${RESET}"
    echo -e "${YELLOW}监听端口: ${PORT}${RESET}"
    echo -e "${YELLOW}PSK 密钥: ${PSK}${RESET}"
    echo -e "${YELLOW}IPv6: true${RESET}"
    echo -e "${YELLOW}DNS 服务器: ${DNS}${RESET}"
    echo -e "${CYAN}--------------------------------${RESET}"

    echo -e "\n${GREEN}服务器地址信息：${RESET}"
    IPV4_ADDR=$(curl -s4 https://api.ipify.org)
    if [ $? -eq 0 ] && [ ! -z "$IPV4_ADDR" ]; then
        IP_COUNTRY_IPV4=$(curl -s http://ipinfo.io/${IPV4_ADDR}/country)
        echo -e "${GREEN}IPv4 地址: ${RESET}${IPV4_ADDR} ${GREEN}所在国家: ${RESET}${IP_COUNTRY_IPV4}"
    fi

    IPV6_ADDR=$(curl -s6 https://api64.ipify.org)
    if [ $? -eq 0 ] && [ ! -z "$IPV6_ADDR" ]; then
        IP_COUNTRY_IPV6=$(curl -s https://ipapi.co/${IPV6_ADDR}/country/)
        echo -e "${GREEN}IPv6 地址: ${RESET}${IPV6_ADDR} ${GREEN}所在国家: ${RESET}${IP_COUNTRY_IPV6}"
    fi

    echo -e "\n${GREEN}Surge 配置格式：${RESET}"
    if [ ! -z "$IPV4_ADDR" ]; then
        echo -e "${GREEN}${IP_COUNTRY_IPV4} = snell, ${IPV4_ADDR}, ${PORT}, psk = ${PSK}, version = 4, reuse = true, tfo = true${RESET}"
    fi
    if [ ! -z "$IPV6_ADDR" ]; then
        echo -e "${GREEN}${IP_COUNTRY_IPV6} = snell, ${IPV6_ADDR}, ${PORT}, psk = ${PSK}, version = 4, reuse = true, tfo = true${RESET}"
    fi

    echo -e "${CYAN}正在安装管理脚本...${RESET}"
    mkdir -p /usr/local/bin

    cat > /usr/local/bin/snell << 'EOFSCRIPT'
#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}请以 root 权限运行此脚本${RESET}"
    exit 1
fi

echo -e "${CYAN}运行本地管理脚本...${RESET}"
bash "$0"
EOFSCRIPT

    if [ $? -eq 0 ]; then
        chmod +x /usr/local/bin/snell
        if [ $? -eq 0 ]; then
            echo -e "\n${GREEN}管理脚本安装成功！${RESET}"
            echo -e "${YELLOW}您可以在终端输入 'snell' 进入管理菜单。${RESET}"
            echo -e "${YELLOW}注意：需要使用 sudo snell 或以 root 身份运行。${RESET}\n"
        else
            echo -e "\n${RED}设置脚本执行权限失败。${RESET}"
            echo -e "${YELLOW}您可以通过直接运行原脚本来管理 Snell。${RESET}\n"
        fi
    else
        echo -e "\n${RED}创建管理脚本失败。${RESET}"
        echo -e "${YELLOW}您可以通过直接运行原脚本来管理 Snell。${RESET}\n"
    fi
}

# 卸载 Snell
uninstall_snell() {
    echo -e "${CYAN}正在卸载 Snell${RESET}"

    systemctl stop snell
    systemctl disable snell

    rm -f /lib/systemd/system/snell.service
    rm -f /usr/local/bin/snell-server
    rm -rf ${SNELL_CONF_DIR}
    rm -f /usr/local/bin/snell

    systemctl daemon-reload

    echo -e "${GREEN}Snell 已成功卸载${RESET}"
}

# 重启 Snell
restart_snell() {
    echo -e "${YELLOW}正在重启 Snell 服务...${RESET}"

    systemctl restart snell
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Snell 服务已成功重启。${RESET}"
    else
        echo -e "${RED}重启 Snell 服务失败。${RESET}"
    fi
}

# 检查服务状态并显示
check_and_show_status() {
    echo -e "\n${CYAN}=============== 服务状态检查 ===============${RESET}"

    if command -v snell-server &> /dev/null; then
        local total_snell_memory=0
        local total_snell_cpu=0

        if systemctl is-active snell &> /dev/null; then
            local main_pid=$(systemctl show -p MainPID snell | cut -d'=' -f2)
            if [ ! -z "$main_pid" ] && [ "$main_pid" != "0" ]; then
                local mem=$(ps -o rss= -p $main_pid 2>/dev/null)
                local cpu=$(ps -o %cpu= -p $main_pid 2>/dev/null)
                if [ ! -z "$mem" ]; then
                    total_snell_memory=$((total_snell_memory + mem))
                fi
                if [ ! -z "$cpu" ]; then
                    total_snell_cpu=$(echo "$total_snell_cpu + $cpu" | bc -l)
                fi
            fi
            local total_snell_memory_mb=$(echo "scale=2; $total_snell_memory/1024" | bc)
            printf "${GREEN}Snell 已安装${RESET}  ${YELLOW}CPU：%.2f%%${RESET}  ${YELLOW}内存：%.2f MB${RESET}  ${GREEN}运行中${RESET}\n" "$total_snell_cpu" "$total_snell_memory_mb"
        else
            echo -e "${GREEN}Snell 已安装${RESET}  ${YELLOW}未运行${RESET}"
        fi
    else
        echo -e "${YELLOW}Snell 未安装${RESET}"
    fi

    if [ -f "/usr/local/bin/shadow-tls" ]; then
        local stls_total=0
        local stls_running=0
        local total_stls_memory=0
        local total_stls_cpu=0
        declare -A processed_ports

        local snell_services=$(find /etc/systemd/system -name "shadowtls-snell-*.service" 2>/dev/null | sort -u)
        if [ ! -z "$snell_services" ]; then
            while IFS= read -r service_file; do
                local port=$(basename "$service_file" | sed 's/shadowtls-snell-\([0-9]*\)\.service/\1/')
                if [ -z "${processed_ports[$port]}" ]; then
                    processed_ports[$port]=1
                    stls_total=$((stls_total + 1))
                    if systemctl is-active "shadowtls-snell-${port}" &> /dev/null; then
                        stls_running=$((stls_running + 1))
                        local stls_pid=$(systemctl show -p MainPID "shadowtls-snell-${port}" | cut -d'=' -f2)
                        if [ ! -z "$stls_pid" ] && [ "$stls_pid" != "0" ]; then
                            local mem=$(ps -o rss= -p $stls_pid 2>/dev/null)
                            local cpu=$(ps -o %cpu= -p $stls_pid 2>/dev/null)
                            if [ ! -z "$mem" ]; then
                                total_stls_memory=$((total_stls_memory + mem))
                            fi
                            if [ ! -z "$cpu" ]; then
                                total_stls_cpu=$(echo "$total_stls_cpu + $cpu" | bc -l)
                            fi
                        fi
                    fi
                fi
            done <<< "$snell_services"
        fi

        if [ $stls_total -gt 0 ]; then
            local total_stls_memory_mb=$(echo "scale=2; $total_stls_memory/1024" | bc)
            printf "${GREEN}ShadowTLS 已安装${RESET}  ${YELLOW}CPU：%.2f%%${RESET}  ${YELLOW}内存：%.2f MB${RESET}  ${GREEN}运行中：${stls_running}/${stls_total}${RESET}\n" "$total_stls_cpu" "$total_stls_memory_mb"
        else
            echo -e "${YELLOW}ShadowTLS 未安装${RESET}"
        fi
    else
        echo -e "${YELLOW}ShadowTLS 未安装${RESET}"
    fi

    echo -e "${CYAN}============================================${RESET}\n"
}

# 查看配置
view_snell_config() {
    echo -e "${GREEN}Snell 配置信息:${RESET}"
    echo -e "${CYAN}================================${RESET}"

    IPV4_ADDR=$(curl -s4 https://api.ipify.org)
    if [ $? -eq 0 ] && [ ! -z "$IPV4_ADDR" ]; then
        IP_COUNTRY_IPV4=$(curl -s http://ipinfo.io/${IPV4_ADDR}/country)
        echo -e "${GREEN}IPv4 地址: ${RESET}${IPV4_ADDR} ${GREEN}所在国家: ${RESET}${IP_COUNTRY_IPV4}"
    fi

    IPV6_ADDR=$(curl -s6 https://api64.ipify.org)
    if [ $? -eq 0 ] && [ ! -z "$IPV6_ADDR" ]; then
        IP_COUNTRY_IPV6=$(curl -s https://ipapi.co/${IPV6_ADDR}/country/)
        echo -e "${GREEN}IPv6 地址: ${RESET}${IPV6_ADDR} ${GREEN}所在国家: ${RESET}${IP_COUNTRY_IPV6}"
    fi

    if [ -z "$IPV4_ADDR" ] && [ -z "$IPV6_ADDR" ]; then
        echo -e "${RED}无法获取到公网 IP 地址，请检查网络连接。${RESET}"
        return
    fi

    if [ -f "$SNELL_CONF_FILE" ]; then
        echo -e "\n${GREEN}配置信息：${RESET}"
        local port=$(grep -E '^listen' "$SNELL_CONF_FILE" | sed -n 's/.*::0:\([0-9]*\)/\1/p')
        local psk=$(grep -E '^psk' "$SNELL_CONF_FILE" | awk -F'=' '{print $2}' | tr -d ' ')
        local ipv6=$(grep -E '^ipv6' "$SNELL_CONF_FILE" | awk -F'=' '{print $2}' | tr -d ' ')
        local dns=$(grep -E '^dns' "$SNELL_CONF_FILE" | awk -F'=' '{print $2}' | tr -d ' ')

        echo -e "${YELLOW}端口: ${port}${RESET}"
        echo -e "${YELLOW}PSK: ${psk}${RESET}"
        echo -e "${YELLOW}IPv6: ${ipv6}${RESET}"
        echo -e "${YELLOW}DNS: ${dns}${RESET}"

        echo -e "\n${GREEN}Surge 配置格式：${RESET}"
        if [ ! -z "$IPV4_ADDR" ]; then
            echo -e "${GREEN}${IP_COUNTRY_IPV4} = snell, ${IPV4_ADDR}, ${port}, psk = ${psk}, version = 4, reuse = true, tfo = true${RESET}"
        fi
        if [ ! -z "$IPV6_ADDR" ]; then
            echo -e "${GREEN}${IP_COUNTRY_IPV6} = snell, ${IPV6_ADDR}, ${port}, psk = ${psk}, version = 4, reuse = true, tfo = true${RESET}"
        fi
    fi

    if shadowtls_config=$(get_shadowtls_config); then
        IFS='|' read -r stls_psk stls_domain stls_port <<< "$shadowtls_config"
        echo -e "\n${YELLOW}=== ShadowTLS 配置 ===${RESET}"
        echo -e "${GREEN}服务器配置：${RESET}"
        echo -e "  - 监听端口：${stls_port}"
        echo -e "  - 密码：${stls_psk}"
        echo -e "  - SNI：${stls_domain}"
        echo -e "  - 版本：3"

        if [ -f "$SNELL_CONF_FILE" ]; then
            local port=$(grep -E '^listen' "$SNELL_CONF_FILE" | sed -n 's/.*::0:\([0-9]*\)/\1/p')
            local psk=$(grep -E '^psk' "$SNELL_CONF_FILE" | awk -F'=' '{print $2}' | tr -d ' ')
            echo -e "\n${GREEN}ShadowTLS 配置：${RESET}"
            echo -e "\n${GREEN}Surge 配置格式：${RESET}"
            if [ ! -z "$IPV4_ADDR" ]; then
                echo -e "${GREEN}${IP_COUNTRY_IPV4} = snell, ${IPV4_ADDR}, ${stls_port}, psk = ${psk}, version = 4, reuse = true, tfo = true, shadow-tls-password = ${stls_psk}, shadow-tls-sni = ${stls_domain}, shadow-tls-version = 3${RESET}"
            fi
            if [ ! -z "$IPV6_ADDR" ]; then
                echo -e "${GREEN}${IP_COUNTRY_IPV6} = snell, ${IPV6_ADDR}, ${stls_port}, psk = ${psk}, version = 4, reuse = true, tfo = true, shadow-tls-password = ${stls_psk}, shadow-tls-sni = ${stls_domain}, shadow-tls-version = 3${RESET}"
            fi
        fi
    fi

    echo -e "\n${YELLOW}注意：${RESET}"
    echo -e "1. Snell 仅支持 Surge 客户端"
    echo -e "2. 请将配置中的服务器地址替换为实际可用的地址"
    read -p "按任意键返回主菜单..."
}

# 获取当前安装的 Snell 版本
get_current_snell_version() {
    CURRENT_VERSION=$(snell-server --v 2>&1 | grep -oP 'v[0-9]+\.[0-9]+\.[0-9]+')
    if [ -z "$CURRENT_VERSION" ]; then
        echo -e "${RED}无法获取当前 Snell 版本。${RESET}"
        exit 1
    fi
}

# 检查 Snell 更新
check_snell_update() {
    get_latest_snell_version
    get_current_snell_version

    if ! version_greater_equal "$CURRENT_VERSION" "$SNELL_VERSION"; then
        echo -e "${YELLOW}当前 Snell 版本: ${CURRENT_VERSION}，最新版本: ${SNELL_VERSION}${RESET}"
        echo -e "${CYAN}是否更新 Snell? [y/N]${RESET}"
        read -r choice
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            install_snell
        else
            echo -e "${CYAN}已取消更新。${RESET}"
        fi
    else
        echo -e "${GREEN}当前已是最新版本 (${CURRENT_VERSION})。${RESET}"
    fi
}

# 获取 ShadowTLS 配置
get_shadowtls_config() {
    local main_port=$(get_snell_port)
    if [ -z "$main_port" ]; then
        return 1
    fi

    local service_name="shadowtls-snell-${main_port}"
    if ! systemctl is-active --quiet "$service_name"; then
        return 1
    fi

    local service_file="/etc/systemd/system/${service_name}.service"
    if [ ! -f "$service_file" ]; then
        return 1
    fi

    local exec_line=$(grep "ExecStart=" "$service_file")
    if [ -z "$exec_line" ]; then
        return 1
    fi

    local tls_domain=$(echo "$exec_line" | grep -o -- "--tls [^ ]*" | cut -d' ' -f2)
    local password=$(echo "$exec_line" | grep -o -- "--password [^ ]*" | cut -d' ' -f2)
    local listen_part=$(echo "$exec_line" | grep -o -- "--listen [^ ]*" | cut -d' ' -f2)
    local listen_port=$(echo "$listen_part" | grep -o '[0-9]*$')

    if [ -z "$tls_domain" ] || [ -z "$password" ] || [ -z "$listen_port" ]; then
        return 1
    fi

    echo "${password}|${tls_domain}|${listen_port}"
    return 0
}

# 初始检查
initial_check() {
    check_root
    check_bc
    check_and_migrate_config
    check_and_show_status
}

initial_check

# 主菜单
show_menu() {
    clear
    echo -e "${CYAN}============================================${RESET}"
    echo -e "${CYAN}          Snell 管理脚本 v${current_version}${RESET}"
    echo -e "${CYAN}============================================${RESET}"

    check_and_show_status

    echo -e "${YELLOW}=== 基础功能 ===${RESET}"
    echo -e "${GREEN}1.${RESET} 安装 Snell"
    echo -e "${GREEN}2.${RESET} 卸载 Snell"
    echo -e "${GREEN}3.${RESET} 查看配置"
    echo -e "${GREEN}4.${RESET} 重启服务"

    echo -e "\n${YELLOW}=== 增强功能 ===${RESET}"
    echo -e "${GREEN}5.${RESET} ShadowTLS 管理"
    echo -e "${GREEN}6.${RESET} BBR 管理"

    echo -e "\n${YELLOW}=== 系统功能 ===${RESET}"
    echo -e "${GREEN}7.${RESET} 检查更新"
    echo -e "${GREEN}8.${RESET} 查看服务状态"
    echo -e "${GREEN}0.${RESET} 退出脚本"

    echo -e "${CYAN}============================================${RESET}"
    read -rp "请输入选项 [0-8]: " num
}

# 开启 BBR
setup_bbr() {
    echo -e "${CYAN}正在获取并执行 BBR 管理脚本...${RESET}"
    bash <(curl -sL https://raw.githubusercontent.com/NeoLeoX/NewWorld/refs/heads/main/BBR.sh)
    echo -e "${GREEN}BBR 管理操作完成${RESET}"
    sleep 1
}

# ShadowTLS 管理
setup_shadowtls() {
    echo -e "${CYAN}正在执行 ShadowTLS 管理脚本...${RESET}"
    bash <(curl -sL https://raw.githubusercontent.com/NeoLeoX/NewWorld/refs/heads/main/ShadowTLS.sh)
    echo -e "${GREEN}ShadowTLS 管理操作完成${RESET}"
    sleep 1
}

# 获取 Snell 端口
get_snell_port() {
    if [ -f "${SNELL_CONF_FILE}" ]; then
        grep -E '^listen' "${SNELL_CONF_FILE}" | sed -n 's/.*::0:\([0-9]*\)/\1/p'
    fi
}

# 主循环
while true; do
    show_menu
    case "$num" in
        1)
            install_snell
            ;;
        2)
            uninstall_snell
            ;;
        3)
            view_snell_config
            ;;
        4)
            restart_snell
            ;;
        5)
            setup_shadowtls
            ;;
        6)
            setup_bbr
            ;;
        7)
            check_snell_update
            ;;
        8)
            check_and_show_status
            read -p "按任意键继续..."
            ;;
        0)
            echo -e "${GREEN}感谢使用，再见！${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}请输入正确的选项 [0-8]${RESET}"
            ;;
    esac
    echo -e "\n${CYAN}按任意键返回主菜单...${RESET}"
    read -n 1 -s -r
done
