#!/bin/bash
# =========================================
# 描述: 这个脚本用于配置和安装 BBR，包括 XanMod 官方 BBR v3
# =========================================

# 定义颜色变量，用于终端输出美化
RED='\033[0;31m'    # 红色
GREEN='\033[0;32m'  # 绿色
YELLOW='\033[0;33m' # 黄色
CYAN='\033[0;36m'   # 青色
RESET='\033[0m'     # 重置颜色

# 检查是否以 root 权限运行
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}请以 root 权限运行此脚本。${RESET}"
    exit 1
fi

# 配置系统参数和启用 BBR 的函数
configure_system_and_bbr() {
    echo -e "${YELLOW}配置系统参数和 BBR...${RESET}"
    
    # 将优化参数写入 sysctl.conf 文件
    cat > /etc/sysctl.conf << EOF
fs.file-max = 6815744                  # 设置最大文件句柄数
net.ipv4.tcp_no_metrics_save = 1       # 不保存 TCP 指标
net.ipv4.tcp_ecn = 0                   # 禁用显式拥塞通知
net.ipv4.tcp_frto = 0                  # 禁用前向重传优化
net.ipv4.tcp_mtu_probing = 0           # 禁用 MTU 探测
net.ipv4.tcp_rfc1337 = 0               # 禁用 RFC 1337 时间等待保护
net.ipv4.tcp_sack = 1                  # 启用选择性确认
net.ipv4.tcp_fack = 1                  # 启用前向确认
net.ipv4.tcp_window_scaling = 1        # 启用 TCP 窗口缩放
net.ipv4.tcp_adv_win_scale = 1         # 设置高级窗口缩放因子
net.ipv4.tcp_moderate_rcvbuf = 1       # 启用适度接收缓冲区
net.core.rmem_max = 33554432           # 设置最大读取内存缓冲区
net.core.wmem_max = 33554432           # 设置最大写入内存缓冲区
net.ipv4.tcp_rmem = 4096 87380 33554432 # 设置 TCP 读取缓冲区
net.ipv4.tcp_wmem = 4096 16384 33554432 # 设置 TCP 写入缓冲区
net.ipv4.udp_rmem_min = 8192           # 设置最小 UDP 读取缓冲区
net.ipv4.udp_wmem_min = 8192           # 设置最小 UDP 写入缓冲区
net.ipv4.ip_forward = 1                # 启用 IP 转发
net.ipv4.conf.all.route_localnet = 1   # 允许路由本地网络
net.ipv4.conf.all.forwarding = 1       # 启用所有接口转发
net.ipv4.conf.default.forwarding = 1   # 启用默认接口转发
net.core.default_qdisc = fq            # 设置默认队列规则为 fq
net.ipv4.tcp_congestion_control = bbr  # 设置拥塞控制为 BBR
net.ipv6.conf.all.forwarding = 1       # 启用 IPv6 所有接口转发
net.ipv6.conf.default.forwarding = 1   # 启用 IPv6 默认接口转发
EOF

    # 应用配置
    sysctl -p

    # 检查 BBR 是否启用成功
    if lsmod | grep -q tcp_bbr && sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        echo -e "${GREEN}BBR 和系统参数已成功配置。${RESET}"
    else
        echo -e "${YELLOW}BBR 或系统参数配置可能需要重启系统才能生效。${RESET}"
    fi
}

# 启用标准 BBR 的函数
enable_bbr() {
    echo -e "${YELLOW}正在启用标准 BBR...${RESET}"
    
    # 检查是否已启用 BBR
    if lsmod | grep -q "^tcp_bbr" && sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        echo -e "${GREEN}BBR 已经启用。${RESET}"
        return 0
    fi
    
    # 如果未启用，调用配置函数
    configure_system_and_bbr
}

# 安装 XanMod BBR v3（遵循官方方法）
install_xanmod_bbr() {
    echo -e "${YELLOW}准备安装 XanMod 内核 (BBR v3)...${RESET}"
    
    # 检查系统架构
    if [ "$(uname -m)" != "x86_64" ]; then
        echo -e "${RED}错误: 仅支持 x86_64 架构${RESET}"
        return 1
    fi
    
    # 检查操作系统是否为 Debian/Ubuntu
    if ! grep -Eqi "debian|ubuntu" /etc/os-release; then
        echo -e "${RED}错误: 仅支持 Debian/Ubuntu 系统${RESET}"
        return 1
    fi
    
    # 下载并运行 CPU 兼容性检查脚本
    echo -e "${YELLOW}检查 CPU 兼容性...${RESET}"
    wget -q https://dl.xanmod.org/check_x86-64_psabi.sh -O check_x86-64_psabi.sh
    chmod +x check_x86-64_psabi.sh
    ./check_x86-64_psabi.sh
    rm -f check_x86-64_psabi.sh
    
    # 提示用户选择 XanMod 版本
    echo -e "${YELLOW}默认安装 linux-xanmod-x64v3，您可以根据 CPU 检查结果手动修改。${RESET}"
    read -p "请输入要安装的版本（x64v1/x64v2/x64v3/x64v4，默认 x64v3）: " version
    version=${version:-x64v3}  # 如果用户未输入，默认使用 x64v3
    case "$version" in
        x64v1|x64v2|x64v3|x64v4) ;;
        *) echo -e "${RED}无效版本，使用默认 x64v3${RESET}"; version="x64v3" ;;
    esac
    
    # 注册 XanMod 的 PGP 密钥
    echo -e "${YELLOW}注册 XanMod PGP 密钥...${RESET}"
    wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
    
    # 添加 XanMod 存储库
    echo -e "${YELLOW}添加 XanMod 存储库...${RESET}"
    echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
    
    # 更新包列表并安装指定版本的 XanMod 内核
    echo -e "${YELLOW}更新包列表并安装 XanMod 内核...${RESET}"
    apt update -y
    if apt install -y "linux-xanmod-$version"; then
        echo -e "${GREEN}XanMod 内核 ($version) 安装成功${RESET}"
    else
        echo -e "${RED}XanMod 内核安装失败，请检查网络或存储库${RESET}"
        return 1
    fi
    
    # 配置 BBR 参数
    configure_system_and_bbr
    
    # 提示用户重启系统
    echo -e "${GREEN}XanMod 内核安装完成，请重启系统以使用新内核${RESET}"
    read -p "是否现在重启系统？[y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        reboot
    fi
}

# 手动编译安装 BBR v3 的函数
install_bbr3_manual() {
    echo -e "${YELLOW}准备手动编译安装 BBR v3...${RESET}"
    
    # 更新包列表并安装编译依赖
    apt update
    apt install -y build-essential git
    
    # 克隆 BBR v3 源码
    git clone -b v3 https://github.com/google/bbr.git
    cd bbr
    
    # 编译并安装
    make
    make install
    
    # 配置系统参数
    configure_system_and_bbr
    
    # 提示安装完成并询问是否重启
    echo -e "${GREEN}BBR v3 编译安装完成${RESET}"
    read -p "是否现在重启系统？[y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        reboot
    fi
}

# 主菜单函数
main_menu() {
    while true; do
        echo -e "\n${CYAN}BBR 管理菜单${RESET}"
        echo -e "${YELLOW}1. 启用标准 BBR${RESET}"
        echo -e "${YELLOW}2. 安装 BBR v3 (XanMod 官方版本)${RESET}"
        echo -e "${YELLOW}3. 安装 BBR v3 (手动编译)${RESET}"
        echo -e "${YELLOW}4. 返回上级菜单${RESET}"
        echo -e "${YELLOW}5. 退出脚本${RESET}"
        read -p "请选择操作 [1-5]: " choice

        # 根据用户选择执行对应操作
        case "$choice" in
            1) enable_bbr ;;
            2) install_xanmod_bbr ;;
            3) install_bbr3_manual ;;
            4) return 0 ;;
            5) exit 0 ;;
            *) echo -e "${RED}无效的选择${RESET}" ;;
        esac
    done
}

# 运行主菜单
main_menu
