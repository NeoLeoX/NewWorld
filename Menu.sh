#!/bin/bash
# =========================================
# 描述: 用于统一管理 BBR、Snell、ss-2022 和 ShadowTLS
# =========================================

# 定义颜色代码
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

# 安装全局命令
install_global_command() {
    echo -e "${CYAN}正在安装全局命令...${RESET}"
    curl -L -s https://raw.githubusercontent.com/NeoLeoX/NewWorld/refs/heads/main/Menu.sh -o /usr/local/bin/menu.sh
    chmod +x "/usr/local/bin/menu.sh"
    if [ -f "/usr/local/bin/menu" ]; then
        rm -f "/usr/local/bin/menu"
    fi
    ln -s "/usr/local/bin/menu.sh" "/usr/local/bin/menu"
    echo -e "${GREEN}安装成功！现在您可以在任何位置使用 'menu' 命令来启动管理脚本${RESET}"
}

# 检查并安装依赖
check_dependencies() {
    local deps=("bc")
    local need_update=false
    echo -e "${CYAN}正在检查依赖...${RESET}"
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo -e "${YELLOW}未检测到 ${dep}，准备安装...${RESET}"
            need_update=true
            break
        fi
    done
    if [ "$need_update" = true ]; then
        if [ -x "$(command -v apt)" ]; then
            apt update
            for dep in "${deps[@]}"; do
                if ! command -v "$dep" &> /dev/null; then
                    echo -e "${CYAN}正在安装 ${dep}...${RESET}"
                    apt install -y "$dep"
                fi
            done
        elif [ -x "$(command -v yum)" ]; then
            for dep in "${deps[@]}"; do
                if ! command -v "$dep" &> /dev/null; then
                    echo -e "${CYAN}正在安装 ${dep}...${RESET}"
                    yum install -y "$dep"
                fi
            done
        else
            echo -e "${RED}未支持的包管理器，请手动安装以下依赖：${deps[*]}${RESET}"
            exit 1
        fi
    fi
    echo -e "${GREEN}所有依赖已满足${RESET}"
}

# 获取 CPU 使用率
get_cpu_usage() {
    local pid=$1
    local cpu_usage=0
    local cpu_cores=$(nproc)
    if [ ! -z "$pid" ] && [ "$pid" != "0" ]; then
        cpu_usage=$(top -b -n 2 -d 0.2 -p "$pid" | tail -1 | awk '{print $9}')
        if [ -z "$cpu_usage" ]; then
            cpu_usage=$(ps -p "$pid" -o %cpu= 2>/dev/null || echo 0)
        fi
        cpu_usage=$(echo "scale=2; $cpu_usage / $cpu_cores" | bc -l)
    fi
    echo "$cpu_usage"
}

# 检查是否以 root 权限运行
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}请以 root 权限运行此脚本${RESET}"
        exit 1
    fi
}

# 检查服务状态并显示
check_and_show_status() {
    local cpu_cores=$(nproc)
    echo -e "\n${CYAN}=== 服务状态检查 ===${RESET}"
    echo -e "${CYAN}系统 CPU 核心数：${cpu_cores}${RESET}"

    # 检查 Snell 状态
    if command -v snell-server &> /dev/null; then
        local user_count=0
        local running_count=0
        local total_snell_memory=0
        local total_snell_cpu=0
        if systemctl is-active snell &> /dev/null; then
            user_count=$((user_count + 1))
            running_count=$((running_count + 1))
            local main_pid=$(systemctl show -p MainPID snell | cut -d'=' -f2)
            if [ ! -z "$main_pid" ] && [ "$main_pid" != "0" ]; then
                local mem=$(ps -o rss= -p $main_pid 2>/dev/null || echo 0)
                local cpu=$(get_cpu_usage "$main_pid")
                total_snell_memory=$((total_snell_memory + ${mem:-0}))
                if [ ! -z "$cpu" ]; then
                    total_snell_cpu=$(echo "$total_snell_cpu + ${cpu:-0}" | bc -l 2>/dev/null || echo "0")
                fi
            fi
        else
            user_count=$((user_count + 1))
        fi
        if [ -d "/etc/snell/users" ]; then
            for user_conf in "/etc/snell/users"/*; do
                if [ -f "$user_conf" ] && [[ "$user_conf" != *"snell-main.conf" ]]; then
                    local port=$(grep -E '^listen' "$user_conf" | sed -n 's/.*::0:\([0-9]*\)/\1/p')
                    if [ ! -z "$port" ]; then
                        user_count=$((user_count + 1))
                        if systemctl is-active --quiet "snell-${port}"; then
                            running_count=$((running_count + 1))
                            local user_pid=$(systemctl show -p MainPID "snell-${port}" | cut -d'=' -f2)
                            if [ ! -z "$user_pid" ] && [ "$user_pid" != "0" ]; then
                                local mem=$(ps -o rss= -p $user_pid 2>/dev/null || echo 0)
                                local cpu=$(get_cpu_usage "$user_pid")
                                total_snell_memory=$((total_snell_memory + ${mem:-0}))
                                if [ ! -z "$cpu" ]; then
                                    total_snell_cpu=$(echo "$total_snell_cpu + ${cpu:-0}" | bc -l 2>/dev/null || echo "0")
                                fi
                            fi
                        fi
                    fi
                fi
            done
        fi
        total_snell_memory=${total_snell_memory:-0}
        total_snell_cpu=${total_snell_cpu:-0}
        local total_snell_memory_mb=$(echo "scale=2; $total_snell_memory/1024" | bc -l 2>/dev/null || echo "0")
        printf "${GREEN}Snell 已安装${RESET}  ${YELLOW}CPU：%.2f%% (每核)${RESET}  ${YELLOW}内存：%.2f MB${RESET}  ${GREEN}运行中：${running_count}/${user_count}${RESET}\n" "${total_snell_cpu:-0}" "${total_snell_memory_mb:-0}"
    else
        echo -e "${YELLOW}Snell 未安装${RESET}"
    fi

    # 检查 ss-2022 状态
    if [[ -e "/usr/local/bin/ss-rust" ]]; then
        local ss_memory=0
        local ss_cpu=0
        local ss_running=0
        if systemctl is-active ss-rust &> /dev/null; then
            ss_running=1
            local ss_pid=$(systemctl show -p MainPID ss-rust | cut -d'=' -f2)
            if [ ! -z "$ss_pid" ] && [ "$ss_pid" != "0" ]; then
                ss_memory=$(ps -o rss= -p $ss_pid 2>/dev/null || echo 0)
                ss_cpu=$(get_cpu_usage "$ss_pid")
            fi
        fi
        local ss_memory_mb=$(echo "scale=2; $ss_memory/1024" | bc)
        printf "${GREEN}ss-2022 已安装${RESET}  ${YELLOW}CPU：%.2f%% (每核)${RESET}  ${YELLOW}内存：%.2f MB${RESET}  ${GREEN}运行中：${ss_running}/1${RESET}\n" "$ss_cpu" "$ss_memory_mb"
    else
        echo -e "${YELLOW}ss-2022 未安装${RESET}"
    fi

    # 检查 ShadowTLS 状态
    if systemctl list-units --type=service | grep -q "shadowtls-"; then
        local stls_total=0
        local stls_running=0
        local total_stls_memory=0
        local total_stls_cpu=0
        while IFS= read -r service; do
            stls_total=$((stls_total + 1))
            if systemctl is-active "$service" &> /dev/null; then
                stls_running=$((stls_running + 1))
                local stls_pid=$(systemctl show -p MainPID "$service" | cut -d'=' -f2)
                if [ ! -z "$stls_pid" ] && [ "$stls_pid" != "0" ]; then
                    local mem=$(ps -o rss= -p $stls_pid 2>/dev/null || echo 0)
                    local cpu=$(get_cpu_usage "$stls_pid")
                    total_stls_memory=$((total_stls_memory + mem))
                    total_stls_cpu=$(echo "$total_stls_cpu + $cpu" | bc -l)
                fi
            fi
        done < <(systemctl list-units --type=service --all --no-legend | grep "shadowtls-" | awk '{print $1}')
        if [ $stls_total -gt 0 ]; then
            local total_stls_memory_mb=$(echo "scale=2; $total_stls_memory/1024" | bc)
            printf "${GREEN}ShadowTLS 已安装${RESET}  ${YELLOW}CPU：%.2f%% (每核)${RESET}  ${YELLOW}内存：%.2f MB${RESET}  ${GREEN}运行中：${stls_running}/${stls_total}${RESET}\n" "$total_stls_cpu" "$total_stls_memory_mb"
        else
            echo -e "${YELLOW}ShadowTLS 未安装${RESET}"
        fi
    else
        echo -e "${YELLOW}ShadowTLS 未安装${RESET}"
    fi

    # 检查 BBR 状态
    local bbr_status=""
    local sysctl_bbr=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local kernel_version=$(uname -r)
    if [[ "$kernel_version" =~ "xanmod" ]]; then
        bbr_status="XanMod 内核"
    elif [[ "$sysctl_bbr" == "bbr" ]]; then
        bbr_status="启用 BBR"
    else
        bbr_status="未启用 BBR"
    fi
    if [[ -n "$bbr_status" ]]; then
        echo -e "${GREEN}BBR 状态${RESET}  ${YELLOW}${bbr_status}${RESET}"
    else
        echo -e "${YELLOW}无法检测 BBR 状态${RESET}"
    fi
    echo -e "${CYAN}====================${RESET}\n"
}

# 安装/管理 Snell
manage_snell() {
    bash <(curl -sL https://raw.githubusercontent.com/NeoLeoX/NewWorld/refs/heads/main/Snell.sh)
}

# 安装/管理 ss-2022
manage_ss_rust() {
    bash <(curl -sL https://raw.githubusercontent.com/NeoLeoX/NewWorld/refs/heads/main/ss-2022.sh)
}

# 安装/管理 ShadowTLS
manage_shadowtls() {
    bash <(curl -sL https://raw.githubusercontent.com/NeoLeoX/NewWorld/refs/heads/main/ShadowTLS.sh)
}

# 安装/管理 BBR
manage_bbr() {
    bash <(curl -sL https://raw.githubusercontent.com/NeoLeoX/NewWorld/refs/heads/main/BBR.sh)
}

# 卸载 Snell
uninstall_snell() {
    echo -e "${CYAN}正在卸载 Snell${RESET}"
    systemctl stop snell
    systemctl disable snell
    if [ -d "/etc/snell/users" ]; then
        for user_conf in "/etc/snell/users"/*; do
            if [ -f "$user_conf" ]; then
                local port=$(grep -E '^listen' "$user_conf" | sed -n 's/.*::0:\([0-9]*\)/\1/p')
                if [ ! -z "$port" ]; then
                    echo -e "${YELLOW}正在停止用户服务 (端口: $port)${RESET}"
                    systemctl stop "snell-${port}" 2>/dev/null
                    systemctl disable "snell-${port}" 2>/dev/null
                    rm -f "${SYSTEMD_DIR}/snell-${port}.service"
                fi
            fi
        done
    fi
    rm -f "/lib/systemd/system/${service_name}.service"
    rm -f "${SYSTEMD_DIR}/snell.service"
    rm -f /usr/local/bin/snell-server
    rm -rf /etc/snell
    rm -f /usr/local/bin/snell
    systemctl daemon-reload
    echo -e "${GREEN}Snell 及其所有多用户配置已成功卸载${RESET}"
}

# 卸载 ss-2022
uninstall_ss_rust() {
    echo -e "${CYAN}正在卸载 ss-2022...${RESET}"
    systemctl stop ss-rust 2>/dev/null
    systemctl disable ss-rust 2>/dev/null
    rm -f "/etc/systemd/system/ss-rust.service"
    rm -f "/usr/local/bin/ss-rust"
    rm -rf "/etc/ss-rust"
    systemctl daemon-reload
    echo -e "${GREEN}ss-2022 卸载完成！${RESET}"
}

# 卸载 ShadowTLS
uninstall_shadowtls() {
    echo -e "${CYAN}正在卸载 ShadowTLS...${RESET}"
    while IFS= read -r service; do
        systemctl stop "$service" 2>/dev/null
        systemctl disable "$service" 2>/dev/null
        rm -f "/etc/systemd/system/${service}"
    done < <(systemctl list-units --type=service --all --no-legend | grep "shadowtls-" | awk '{print $1}')
    rm -f "/usr/local/bin/shadow-tls"
    systemctl daemon-reload
    echo -e "${GREEN}ShadowTLS 卸载完成！${RESET}"
}

# 主菜单
show_menu() {
    clear
    echo -e "${CYAN}============================================${RESET}"
    echo -e "${CYAN}          统一管理脚本${RESET}"
    echo -e "${CYAN}============================================${RESET}"
    check_and_show_status
    echo -e "${YELLOW}=== 安装管理 ===${RESET}"
    echo -e "${GREEN}1.${RESET} BBR 安装管理"      # BBR 调整到第1位
    echo -e "${GREEN}2.${RESET} Snell 安装管理"    # 原1变为2
    echo -e "${GREEN}3.${RESET} ss-2022 安装管理"  # 原2变为3
    echo -e "${GREEN}4.${RESET} ShadowTLS 安装管理" # 原3变为4
    echo -e "\n${YELLOW}=== 卸载功能 ===${RESET}"
    echo -e "${GREEN}5.${RESET} 卸载 Snell"
    echo -e "${GREEN}6.${RESET} 卸载 ss-2022"
    echo -e "${GREEN}7.${RESET} 卸载 ShadowTLS"
    echo -e "\n${YELLOW}=== 系统功能 ===${RESET}"
    echo -e "${GREEN}0.${RESET} 退出"
    echo -e "${CYAN}============================================${RESET}"
    echo -e "${GREEN}退出脚本后，输入menu可进入脚本${RESET}"
    echo -e "${CYAN}============================================${RESET}"
    read -rp "请输入选项 [0-7]: " num
}

# 初始检查
check_root
check_dependencies
install_global_command

# 主循环
while true; do
    show_menu
    case "$num" in
        1)
            manage_bbr          # 调整为BBR管理
            ;;
        2)
            manage_snell       # 原1变为2
            ;;
        3)
            manage_ss_rust     # 原2变为3
            ;;
        4)
            manage_shadowtls   # 原3变为4
            ;;
        5)
            uninstall_snell
            ;;
        6)
            uninstall_ss_rust
            ;;
        7)
            uninstall_shadowtls
            ;;
        0)
            echo -e "${GREEN}感谢使用，再见！${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}请输入正确的选项 [0-7]${RESET}"
            ;;
    esac
    echo -e "\n${CYAN}按任意键返回主菜单...${RESET}"
    read -n 1 -s -r
done
