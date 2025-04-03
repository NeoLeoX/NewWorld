#!/bin/bash
# =========================================
# 描述: 这个脚本用于配置和安装 BBR，包括 XanMod 官方 BBR v3
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
    # ... (保持原有函数内容不变)
}

# 启用标准BBR
enable_bbr() {
    # ... (保持原有函数内容不变)
}

# 安装 XanMod BBR v3
install_xanmod_bbr() {
    # ... (保持原有函数内容不变)
}

# 手动编译安装BBR v3
install_bbr3_manual() {
    # ... (保持原有函数内容不变)
}

# 添加验证功能
verify_bbr_status() {
    echo -e "${YELLOW}正在验证 BBR 状态...${RESET}"
    
    # 检查当前内核版本
    echo -e "\n${CYAN}当前内核版本:${RESET}"
    uname -r
    
    # 检查可用拥塞控制算法
    echo -e "\n${CYAN}可用拥塞控制算法:${RESET}"
    sysctl net.ipv4.tcp_available_congestion_control
    
    # 检查当前使用的拥塞控制算法
    echo -e "\n${CYAN}当前使用的拥塞控制算法:${RESET}"
    sysctl net.ipv4.tcp_congestion_control
    
    # 检查 BBR 模块是否加载
    echo -e "\n${CYAN}BBR 模块状态:${RESET}"
    if lsmod | grep -q "^tcp_bbr"; then
        echo -e "${GREEN}BBR 模块已加载${RESET}"
    else
        echo -e "${RED}BBR 模块未加载${RESET}"
    fi
    
    # 检查队列规则
    echo -e "\n${CYAN}当前队列规则:${RESET}"
    sysctl net.core.default_qdisc
    
    # 检查 XanMod 内核特征（如果存在）
    if uname -r | grep -q "xanmod"; then
        echo -e "\n${GREEN}检测到 XanMod 内核特征${RESET}"
    fi
    
    # 综合判断
    echo -e "\n${CYAN}状态总结:${RESET}"
    if lsmod | grep -q "^tcp_bbr" && sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        echo -e "${GREEN}BBR 正在正常运行${RESET}"
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
        echo -e "${YELLOW}5. 返回上级菜单${RESET}"
        echo -e "${YELLOW}6. 退出脚本${RESET}"
        read -p "请选择操作 [1-6]: " choice

        case "$choice" in
            1)
                enable_bbr
                ;;
            2)
                install_xanmod_bbr
                ;;
            3)
                install_bbr3_manual
                ;;
            4)
                verify_bbr_status
                ;;
            5)
                return 0
                ;;
            6)
                exit 0
                ;;
            *)
                echo -e "${RED}无效的选择${RESET}"
                ;;
        esac
    done
}

# 运行主菜单
main_menu
