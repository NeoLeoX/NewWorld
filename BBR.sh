#!/bin/bash
# =========================================
# 描述: 用于配置和安装 BBR，包括 XanMod 官方 BBR v3
# =========================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

# 检查是否以 root 权限运行
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}请以 root 权限运行此脚本。${RESET}"
    exit 1
fi

# 配置系统参数和启用 BBR
configure_system_and_bbr() {
    echo -e "${YELLOW}配置系统参数和BBR...${RESET}"
    
    cat > /etc/sysctl.conf << EOF
fs.file-max = 6815744
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_ecn = 0
net.ipv4.tcp_frto = 0
net.ipv4.tcp_mtu_probing = 0
net.ipv4.tcp_rfc1337 = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 16384 33554432
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.ip_forward = 1
net.ipv4.conf.all.route_localnet = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
EOF

    sysctl -p >/dev/null 2>&1

    if lsmod | grep -q tcp_bbr && sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        echo -e "${GREEN}BBR 和系统参数已成功配置。${RESET}"
    else
        echo -e "${YELLOW}BBR 或系统参数配置可能需要重启系统才能生效。${RESET}"
    fi
}

# 启用标准BBR
enable_bbr() {
    echo -e "${YELLOW}正在启用标准BBR...${RESET}"
    
    if lsmod | grep -q "^tcp_bbr" && sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        echo -e "${GREEN}BBR 已经启用。${RESET}"
        return 0
    fi
    
    configure_system_and_bbr
}

# 安装 XanMod BBR v3
install_xanmod_bbr() {
    echo -e "${YELLOW}准备安装 XanMod 内核...${RESET}"
    
    if [ "$(uname -m)" != "x86_64" ]; then
        echo -e "${RED}错误: 仅支持x86_64架构${RESET}"
        return 1
    fi
    
    if ! grep -Eqi "debian|ubuntu" /etc/os-release; then
        echo -e "${RED}错误: 仅支持Debian/Ubuntu系统${RESET}"
        return 1
    fi
    
    apt update -y
    apt install -y gnupg
    
    wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /etc/apt/keyrings/xanmod-archive-keyring.gpg
    echo 'deb [signed-by=/etc/apt/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' > /etc/apt/sources.list.d/xanmod-release.list
    
    apt update -y
    
    echo -e "${YELLOW}尝试安装最新版本内核...${RESET}"
    if apt install -y linux-xanmod-x64v4; then
        echo -e "${GREEN}成功安装最新版本内核${RESET}"
    else
        echo -e "${YELLOW}最新版本安装失败，尝试安装较低版本...${RESET}"
        if apt install -y linux-xanmod-x64v2; then
            echo -e "${GREEN}成功安装兼容版本内核${RESET}"
        else
            echo -e "${RED}内核安装失败${RESET}"
            return 1
        fi
    fi
    
    configure_system_and_bbr
    
    echo -e "${GREEN}XanMod内核安装完成，请重启系统以使用新内核${RESET}"
    read -p "是否现在重启系统？[y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        reboot
    fi
}

# 手动编译安装BBR v3
install_bbr3_manual() {
    echo -e "${YELLOW}准备手动编译安装BBR v3...${RESET}"
    
    apt update
    apt install -y build-essential git
    
    git clone -b v3 https://github.com/google/bbr.git
    cd bbr || exit 1
    
    make
    make install
    
    configure_system_and_bbr
    
    echo -e "${GREEN}BBR v3 编译安装完成${RESET}"
    read -p "是否现在重启系统？[y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        reboot
    fi
}

# 验证 BBR 状态
verify_bbr_status() {
    echo -e "${YELLOW}正在验证 BBR 状态...${RESET}"
    
    echo -e "\n${CYAN}当前内核版本:${RESET}"
    uname -r
    
    echo -e "\n${CYAN}可用拥塞控制算法:${RESET}"
    sysctl net.ipv4.tcp_available_congestion_control
    
    echo -e "\n${CYAN}当前使用的拥塞控制算法:${RESET}"
    sysctl net.ipv4.tcp_congestion_control
    
    echo -e "\n${CYAN}BBR 模块状态:${RESET}"
    if lsmod | grep -q "^tcp_bbr"; then
        echo -e "${GREEN}BBR 模块已加载${RESET}"
    else
        echo -e "${YELLOW}BBR 模块未加载${RESET}"
    fi
    
    echo -e "\n${CYAN}当前队列规则:${RESET}"
    sysctl net.core.default_qdisc
    
    if uname -r | grep -q "xanmod"; then
        echo -e "\n${GREEN}检测到 XanMod 内核特征${RESET}"
    fi
    
    echo -e "\n${CYAN}状态总结:${RESET}"
    if lsmod | grep -q "^tcp_bbr" && sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        echo -e "${GREEN}BBR 正在正常运行${RESET}"
    elif uname -r | grep -q "xanmod" && ! lsmod | grep -q "^tcp_bbr"; then
        echo -e "${YELLOW}检测到 XanMod 内核，但 BBR 模块未加载。可能是内核内置 BBR 支持。${RESET}"
    else
        echo -e "${YELLOW}BBR 未正常运行，请检查配置或重启系统${RESET}"
    fi
}

# 主菜单
main_menu() {
    while true; do
        echo -e "\n${CYAN}BBR 管理菜单${RESET}"
        echo -e "${YELLOW}1. 启用标准 BBR${RESET}"
        echo -e "${YELLOW}2. 安装 BBR v3 (XanMod版本)${RESET}"
        echo -e "${YELLOW}3. 安装 BBR v3 (手动编译)${RESET}"
        echo -e "${YELLOW}4. 验证 BBR 状态${RESET}"
        echo -e "${YELLOW}0. 退出脚本${RESET}"
        read -p "请选择操作 [0-4]: " choice

        case "$choice" in
            1) enable_bbr ;;
            2) install_xanmod_bbr ;;
            3) install_bbr3_manual ;;
            4) verify_bbr_status ;;
            0) exit 0 ;;
            *) echo -e "${RED}无效的选择${RESET}" ;;
        esac
    done
}

# 运行主菜单
main_menu
