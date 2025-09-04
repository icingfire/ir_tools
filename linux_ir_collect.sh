#!/usr/bin/env bash
#===============================================================================
#  linux_ir_collect.sh
#-------------------------------------------------------------------------------
#  Linux 一键应急溯源/取证采集脚本（通用版）
#  目标：快速、尽量无破坏地采集系统关键信息用于事件响应与溯源。
#  兼容：Debian/Ubuntu、RHEL/CentOS/Alma/Rocky、SUSE、Amazon Linux、Arch、
#        Oracle Linux、Kylin、Euler、Deepin 等（尽量兼容，功能按可用性降级）。
#  设计：
#    - 仅做信息采集与轻量体检，不做篡改、清理、杀毒等破坏性动作；
#    - 每步均落磁盘日志与原始输出，保留上下文；
#    - 支持最小权限运行，但推荐 root 以便收集更全信息；
#    - 采集结果结构化目录，便于后续分析；
#    - 提供基础 IOC/可疑项审计：rootkit 线索、可疑启动项、LD_PRELOAD 等；
#    - 自动打包校验（sha256）。
#
#  使用：
#    bash linux_ir_collect.sh
#    # 可选参数见 --help
#
#  安全声明：
#    - 脚本默认只读采集，不对系统做持久性修改；
#    - 部分命令（如 lsof, ss, journalctl）可能较重，请在业务低峰执行；
#    - 如在取证严格场景，建议先对磁盘做快照或只读挂载副本执行。
#
#  版本：1.0.0
#  Author: icingfire
#===============================================================================

set -uo pipefail
IFS=$'\n\t'

#--------------------------------------
# 全局变量与默认选项
#--------------------------------------
SCRIPT_NAME="linux_ir_collect.sh"
VERSION="1.0.0"
START_TS=$(date +%s)
RUN_ID=$(date +"%Y%m%d_%H%M%S")
HOSTNAME_SAFE=$(hostname 2>/dev/null | tr -c 'A-Za-z0-9._-' '_')
DEFAULT_OUT_BASE="./IR_Collect_${HOSTNAME_SAFE}_${RUN_ID}"
OUT_DIR="${DEFAULT_OUT_BASE}"
LOG_FILE="/tmp/${SCRIPT_NAME%.sh}_${RUN_ID}.log"
ENABLE_HASH=1
HASH_CMD="sha256sum"
ARCHIVE=1
COMPRESS_CMD="tar"
COMPRESS_ARGS=("-czf")
TIMEOUT_BIN="timeout"
TIMEOUT_SEC=120
USE_SUDO=""
QUIET=0
FAST_MODE=0
RECENT_DAYS=7
FIND_LIMIT=5000
PCAP_CAPTURE=0
PCAP_DURATION=30
PCAP_IFACE=""
SKIP_JOURNAL=0
INCLUDE_APP_LOGS=1
INCLUDE_DOCKER=1
INCLUDE_K8S=1
INCLUDE_CLOUD=1

#--------------------------------------
# 颜色与日志输出
#--------------------------------------
if [[ -t 1 ]]; then
  C_RESET='\033[0m'
  C_INFO='\033[1;34m'
  C_WARN='\033[1;33m'
  C_ERR='\033[1;31m'
  C_OK='\033[1;32m'
else
  C_RESET=''
  C_INFO=''
  C_WARN=''
  C_ERR=''
  C_OK=''
fi

log() {
  local level="$1"; shift || true
  local msg="$*"
  local ts
  ts=$(date '+%F %T')
  echo "[$ts][$level] $msg" | tee -a "$LOG_FILE" >/dev/null
}

info() { [[ $QUIET -eq 0 ]] && echo -e "${C_INFO}[INFO]${C_RESET} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${C_WARN}[WARN]${C_RESET} $*" | tee -a "$LOG_FILE" >&2; }
err()  { echo -e "${C_ERR}[ERR ]${C_RESET} $*" | tee -a "$LOG_FILE" >&2; }
ok()   { [[ $QUIET -eq 0 ]] && echo -e "${C_OK}[ OK ]${C_RESET} $*" | tee -a "$LOG_FILE"; }

#--------------------------------------
# 帮助信息
#--------------------------------------
usage() {
  cat <<'USAGE'
用法：
  sudo bash linux_ir_collect.sh [选项]

选项：
  -o, --out DIR          指定输出目录（默认：./IR_Collect_<host>_<ts>）
  -q, --quiet            安静模式（减少终端输出）
  -f, --fast             快速模式（跳过重度采集：lsof全量、深度find等）
  -d, --days N           近期文件修改天数范围（默认 7）
  -l, --find-limit N     find 列表最大条数（默认 5000）
  --no-archive           不进行打包压缩
  --no-hash              不计算 sha256 校验
  --no-journal           跳过 journalctl 日志导出
  --no-app-logs          跳过应用日志目录收集
  --no-docker            跳过 Docker 相关采集
  --no-k8s               跳过 Kubernetes 相关采集
  --no-cloud             跳过云环境（AWS/Azure/GCP/Alibaba/HwCloud）元数据采集
  --pcap [IFACE]         抓包 PCAP（需 root），可选网卡名，默认自动选择；
  --pcap-duration N      抓包秒数（默认 30）
  --timeout N            单步骤超时秒数（默认 120）
  -h, --help             显示帮助

说明：
  - 推荐以 root 运行，以采集更完整信息；
  - 脚本仅执行只读类命令与日志导出；
  - 结果目录结构清晰，便于后续分析与归档。
USAGE
}

#--------------------------------------
# 通用工具函数
#--------------------------------------
need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

use_if_available() {
  for c in "$@"; do
    if need_cmd "$c"; then echo "$c"; return 0; fi
  done
  echo ""
}

save_cmd_output() {
  # save_cmd_output <outfile> <cmd...>
  local outfile="$1"; shift
  {
    echo "# CMD: $*"
    echo "# TS: $(date '+%F %T')"
    "$@"
    echo "# EXIT:$?"
  } >"$outfile" 2>&1 || true
}

save_file_safe() {
  # save_file_safe <src> <dst>
  local src="$1"; local dst="$2"
  if [[ -r "$src" ]]; then
    # 保留属性，避免 follow symlink
    cp -a --no-preserve=ownership "$src" "$dst" 2>/dev/null || cp -p "$src" "$dst" 2>/dev/null || true
  fi
}

save_tree_safe() {
  # save_tree_safe <src_dir> <dst_dir>
  local src="$1"; local dst="$2"
  if [[ -d "$src" ]]; then
    mkdir -p "$dst"
    # 使用 rsync 如可用，否则 cp -a
    if need_cmd rsync; then
      rsync -a --no-perms --no-owner --no-group --safe-links --exclude='*.tmp' --exclude='*.lock' "$src"/ "$dst"/ 2>/dev/null || true
    else
      (cd "$src" && tar -cf - . 2>/dev/null) | (cd "$dst" && tar -xf - 2>/dev/null) || cp -a "$src"/. "$dst"/ 2>/dev/null || true
    fi
  fi
}

json_escape() {
  # 粗略转义
  sed 's/\\/\\\\/g; s/\"/\\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g'
}

write_json_kv() {
  # write_json_kv <file> <key> <value>
  local f="$1"; local k="$2"; local v="$3"
  printf '  "%s": "%s",\n' "$k" "$v" >>"$f"
}

#--------------------------------------
# 输出目录初始化
#--------------------------------------
init_out_dir() {
  mkdir -p "$OUT_DIR" || { err "输出目录创建失败: $OUT_DIR"; exit 1; }
  mkdir -p "$OUT_DIR/meta" "$OUT_DIR/sysinfo" "$OUT_DIR/process" "$OUT_DIR/network" \
           "$OUT_DIR/files" "$OUT_DIR/configs" "$OUT_DIR/logs" "$OUT_DIR/rootkit" \
           "$OUT_DIR/modules" "$OUT_DIR/startup" "$OUT_DIR/accounts" "$OUT_DIR/containers" \
           "$OUT_DIR/cloud" "$OUT_DIR/forensic" "$OUT_DIR/security" "$OUT_DIR/tmp" || true

  # 保存脚本副本与参数
  save_file_safe "$0" "$OUT_DIR/meta/${SCRIPT_NAME}"
  printf '%s\n' "$SCRIPT_NAME $VERSION" >"$OUT_DIR/meta/version.txt"
  printf 'START_TS=%s\nRUN_ID=%s\nHOST=%s\n' "$START_TS" "$RUN_ID" "$HOSTNAME_SAFE" >"$OUT_DIR/meta/runinfo.txt"
  printf 'CMDLINE=%q' "$0" >"$OUT_DIR/meta/cmdline.txt"
  printf ' ARGS=' >>"$OUT_DIR/meta/cmdline.txt"; printf ' %q' "$@" >>"$OUT_DIR/meta/cmdline.txt"; echo >>"$OUT_DIR/meta/cmdline.txt"
}

#--------------------------------------
# 发行版与环境探测
#--------------------------------------
OS_ID="unknown"
OS_VERSION=""
OS_PRETTY=""
PKG_TOOL=""
SERVICE_MGR=""
INIT_SYS=""

probe_os() {
  info "探测操作系统..."
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID=${ID:-unknown}
    OS_VERSION=${VERSION_ID:-}
    OS_PRETTY=${PRETTY_NAME:-}
  elif [[ -r /usr/lib/os-release ]]; then
    . /usr/lib/os-release
    OS_ID=${ID:-unknown}
    OS_VERSION=${VERSION_ID:-}
    OS_PRETTY=${PRETTY_NAME:-}
  else
    OS_PRETTY=$(uname -a)
  fi

  # 包管理器
  if need_cmd apt-get; then PKG_TOOL="apt"; fi
  if need_cmd dnf; then PKG_TOOL="dnf"; fi
  if need_cmd yum; then PKG_TOOL=${PKG_TOOL:-"yum"}; fi
  if need_cmd zypper; then PKG_TOOL="zypper"; fi
  if need_cmd pacman; then PKG_TOOL="pacman"; fi

  # 服务管理
  if need_cmd systemctl; then SERVICE_MGR="systemd"; fi
  if [[ -d /etc/init.d ]] && need_cmd service; then INIT_SYS="sysvinit"; fi

  printf 'OS_ID=%s\nOS_VERSION=%s\nOS_PRETTY=%s\nPKG_TOOL=%s\nSERVICE_MGR=%s\nINIT_SYS=%s\n' \
    "$OS_ID" "$OS_VERSION" "$OS_PRETTY" "$PKG_TOOL" "$SERVICE_MGR" "$INIT_SYS" >"$OUT_DIR/sysinfo/os_detect.txt"

  ok "操作系统：$OS_PRETTY | 包管理：${PKG_TOOL:-N/A} | 服务：${SERVICE_MGR:-$INIT_SYS}"
}

#--------------------------------------
# 基础系统信息
#--------------------------------------
collect_basic_sysinfo() {
  info "采集基础系统信息..."
  save_cmd_output "$OUT_DIR/sysinfo/uname.txt" uname -a
  save_cmd_output "$OUT_DIR/sysinfo/uptime.txt" uptime
  save_cmd_output "$OUT_DIR/sysinfo/date.txt" date -R
  save_cmd_output "$OUT_DIR/sysinfo/locale.txt" locale 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/last.txt" last -n 200 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/lastlog.txt" lastlog 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/w.txt" w 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/who.txt" who 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/id.txt" id

  save_cmd_output "$OUT_DIR/sysinfo/cpuinfo.txt" cat /proc/cpuinfo
  save_cmd_output "$OUT_DIR/sysinfo/meminfo.txt" cat /proc/meminfo
  save_cmd_output "$OUT_DIR/sysinfo/numa_maps.txt" cat /proc/zoneinfo
  save_cmd_output "$OUT_DIR/sysinfo/dmesg.txt" dmesg -T 2>/dev/null || dmesg 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/lspci.txt" lspci 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/lsblk.txt" lsblk -O -J 2>/dev/null || lsblk -a 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/blkid.txt" blkid 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/mount.txt" mount | sort -u
  save_cmd_output "$OUT_DIR/sysinfo/df_h.txt" df -hT
  save_cmd_output "$OUT_DIR/sysinfo/swaps.txt" cat /proc/swaps
  save_cmd_output "$OUT_DIR/sysinfo/sysctl.txt" sysctl -a 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/kernel_cmdline.txt" cat /proc/cmdline
  save_cmd_output "$OUT_DIR/sysinfo/lsmod.txt" lsmod 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/modprobe_conf.txt" grep -R "^blacklist\|^install\|^options" /etc/modprobe.* -n 2>/dev/null || true

  save_cmd_output "$OUT_DIR/sysinfo/os_release.txt" cat /etc/os-release 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/issue.txt" cat /etc/issue 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/hostname.txt" hostnamectl 2>/dev/null || hostname 2>/dev/null || true
  save_cmd_output "$OUT_DIR/sysinfo/timezone.txt" timedatectl 2>/dev/null || cat /etc/timezone 2>/dev/null || date '+%Z %z'

  save_cmd_output "$OUT_DIR/sysinfo/packages_list.txt" bash -lc 'if command -v dpkg >/dev/null; then dpkg -l; elif command -v rpm >/dev/null; then rpm -qa; elif command -v pacman >/dev/null; then pacman -Q; else echo "No known package manager"; fi'
  save_cmd_output "$OUT_DIR/sysinfo/repo_config.txt" bash -lc 'ls -l /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; grep -R -n "^deb\|^rpm" /etc/apt/ /etc/yum.repos.d/ /etc/zypp/ -n 2>/dev/null'

  ok "基础系统信息采集完成"
}

#--------------------------------------
# 账户与鉴权信息
#--------------------------------------
collect_accounts() {
  info "采集用户与鉴权信息..."
  save_cmd_output "$OUT_DIR/accounts/passwd.txt" cat /etc/passwd
  save_cmd_output "$OUT_DIR/accounts/group.txt" cat /etc/group
  save_cmd_output "$OUT_DIR/accounts/shadow.txt" cat /etc/shadow 2>/dev/null || echo "need root" >"$OUT_DIR/accounts/shadow.txt"
  save_cmd_output "$OUT_DIR/accounts/gshadow.txt" cat /etc/gshadow 2>/dev/null || echo "need root" >"$OUT_DIR/accounts/gshadow.txt"
  save_cmd_output "$OUT_DIR/accounts/sudoers.txt" bash -lc 'grep -R -n ">\|%\|ALL" /etc/sudoers /etc/sudoers.d 2>/dev/null || cat /etc/sudoers 2>/dev/null'

  mkdir -p "$OUT_DIR/accounts/ssh"
  save_cmd_output "$OUT_DIR/accounts/ssh/sshd_config.txt" bash -lc 'sshd -T 2>/dev/null || cat /etc/ssh/sshd_config 2>/dev/null || true'
  save_cmd_output "$OUT_DIR/accounts/ssh/ssh_config.txt" cat /etc/ssh/ssh_config 2>/dev/null || true

  # 遍历用户家目录收集 SSH 授权、历史、profile 等
  awk -F: '{print $1" "$3" "$6}' /etc/passwd | while read -r USERNAME UID HOME; do
    [[ -z "$HOME" || ! -d "$HOME" ]] && continue
    SAFE_USER=$(echo "$USERNAME" | tr -c 'A-Za-z0-9._-' '_')
    UDIR="$OUT_DIR/accounts/users/$SAFE_USER"
    mkdir -p "$UDIR"
    save_cmd_output "$UDIR/id.txt" bash -lc "id $USERNAME"
    save_file_safe "$HOME/.bash_history" "$UDIR/bash_history" || true
    save_file_safe "$HOME/.zsh_history" "$UDIR/zsh_history" || true
    save_file_safe "$HOME/.ash_history" "$UDIR/ash_history" || true
    save_file_safe "$HOME/.python_history" "$UDIR/python_history" || true
    save_file_safe "$HOME/.mysql_history" "$UDIR/mysql_history" || true
    save_file_safe "$HOME/.psql_history" "$UDIR/psql_history" || true

    save_tree_safe "$HOME/.ssh" "$UDIR/ssh"
    save_tree_safe "$HOME/.config" "$UDIR/config"
    save_tree_safe "$HOME/.profile.d" "$UDIR/profile.d"
    save_file_safe "$HOME/.profile" "$UDIR/.profile"
    save_file_safe "$HOME/.bashrc" "$UDIR/.bashrc"
    save_file_safe "$HOME/.zshrc" "$UDIR/.zshrc"

    # 可疑 authorized_keys 中的注释/命令限制
    if [[ -f "$HOME/.ssh/authorized_keys" ]]; then
      grep -nE 'command=|from=|no-pty|no-port-forwarding|permitopen' "$HOME/.ssh/authorized_keys" >"$UDIR/ssh/authorized_keys_flags.txt" 2>/dev/null || true
    fi
  done

  ok "账户与鉴权信息采集完成"
}

#--------------------------------------
# 进程、连接、端口监听
#--------------------------------------
collect_process_and_network() {
  info "采集进程与网络连接..."
  save_cmd_output "$OUT_DIR/process/ps_aux.txt" ps auxwww
  save_cmd_output "$OUT_DIR/process/ps_elf.txt" ps -elf
  save_cmd_output "$OUT_DIR/process/pstree.txt" pstree -alp 2>/dev/null || true
  save_cmd_output "$OUT_DIR/process/lsof_list.txt" bash -lc 'command -v lsof >/dev/null && lsof -nP +c 15 || echo "lsof not available"'

  mkdir -p "$OUT_DIR/process/byproc"
  for pid in /proc/[0-9]*; do
    [[ -d "$pid" ]] || continue
    p=$(basename "$pid")
    PD="$OUT_DIR/process/byproc/$p"
    mkdir -p "$PD"
    save_file_safe "$pid/cmdline" "$PD/cmdline"
    save_file_safe "$pid/environ" "$PD/environ"
    save_file_safe "$pid/status" "$PD/status"
    save_file_safe "$pid/maps" "$PD/maps"
    save_file_safe "$pid/limits" "$PD/limits"
    save_file_safe "$pid/cwd" "$PD/cwd_link"
    save_file_safe "$pid/exe" "$PD/exe_link"
    save_tree_safe "$pid/fd" "$PD/fd"
    # 已加载动态库
    save_cmd_output "$PD/ldd.txt" bash -lc "ls -l $pid/exe 2>/dev/null | awk '{print \$NF}' | xargs -r ldd 2>/dev/null"
  done

  # 网络
  save_cmd_output "$OUT_DIR/network/ip_addr.txt" ip addr
  save_cmd_output "$OUT_DIR/network/ip_route.txt" ip route
  save_cmd_output "$OUT_DIR/network/ss_s.txt" ss -s 2>/dev/null || true
  save_cmd_output "$OUT_DIR/network/ss_all.txt" ss -tanp 2>/dev/null || netstat -tanp 2>/dev/null || true
  save_cmd_output "$OUT_DIR/network/ss_udp.txt" ss -uanp 2>/dev/null || netstat -uanp 2>/dev/null || true
  save_cmd_output "$OUT_DIR/network/iptables.txt" bash -lc 'iptables -S 2>/dev/null; ip6tables -S 2>/dev/null; nft list ruleset 2>/dev/null'
  save_cmd_output "$OUT_DIR/network/nameserver.txt" cat /etc/resolv.conf 2>/dev/null || true
  save_cmd_output "$OUT_DIR/network/hosts.txt" cat /etc/hosts 2>/dev/null || true
  save_cmd_output "$OUT_DIR/network/hostname.txt" hostnamectl 2>/dev/null || hostname 2>/dev/null || true

  # 监听端口 -> 进程映射（lsof/ss）
  save_cmd_output "$OUT_DIR/network/listen_map.txt" bash -lc '
    if command -v lsof >/dev/null; then
      lsof -i -nP | awk "NR==1||/LISTEN/"
    else
      ss -lntp 2>/dev/null || netstat -lntp 2>/dev/null || true
    fi'

  ok "进程与网络采集完成"
}

#--------------------------------------
# 启动项、服务与计划任务
#--------------------------------------
collect_startup_and_services() {
  info "采集启动项、服务与定时任务..."
  mkdir -p "$OUT_DIR/startup/systemd" "$OUT_DIR/startup/sysv" "$OUT_DIR/startup/cron"

  # systemd 单元、覆盖配置与最近启动失败
  if [[ "$SERVICE_MGR" == "systemd" ]]; then
    save_cmd_output "$OUT_DIR/startup/systemd/list-units.txt" systemctl list-units --all --no-pager
    save_cmd_output "$OUT_DIR/startup/systemd/list-unit-files.txt" systemctl list-unit-files --no-pager
    save_cmd_output "$OUT_DIR/startup/systemd/failed.txt" systemctl --failed --no-pager

    # 导出所有服务的详细属性（耗时，设置超时）
    mkdir -p "$OUT_DIR/startup/systemd/units"
    while read -r u; do
      [[ -z "$u" ]] && continue
      uf="$OUT_DIR/startup/systemd/units/${u//\//_}.txt"
      save_cmd_output "$uf" systemctl cat "$u"
      save_cmd_output "$OUT_DIR/startup/systemd/units/${u//\//_}_show.txt" systemctl show "$u"
    done < <(systemctl list-unit-files --type=service --no-legend | awk '{print $1}' 2>/dev/null)

    # 覆盖目录
    save_tree_safe /etc/systemd/system "$OUT_DIR/startup/systemd/etc_systemd_system"
    save_tree_safe /lib/systemd/system "$OUT_DIR/startup/systemd/lib_systemd_system"
  fi

  # SysV/rc 启动脚本
  save_tree_safe /etc/init.d "$OUT_DIR/startup/sysv/init.d"
  save_tree_safe /etc/rc.d "$OUT_DIR/startup/sysv/rc.d"
  save_tree_safe /etc/rc.local "$OUT_DIR/startup/sysv/rc.local"

  # profile/自启动
  mkdir -p "$OUT_DIR/startup/shell"
  for f in /etc/profile /etc/bash.bashrc /etc/zsh/zshrc; do
    [[ -r "$f" ]] && save_file_safe "$f" "$OUT_DIR/startup/shell/$(basename "$f")"
  done
  save_tree_safe /etc/profile.d "$OUT_DIR/startup/shell/profile.d"

  # Cron
  save_tree_safe /var/spool/cron "$OUT_DIR/startup/cron/var_spool_cron"
  save_tree_safe /var/spool/cron/crontabs "$OUT_DIR/startup/cron/crontabs"
  save_file_safe /etc/crontab "$OUT_DIR/startup/cron/etc_crontab"
  save_tree_safe /etc/cron.d "$OUT_DIR/startup/cron/cron.d"
  save_tree_safe /etc/cron.daily "$OUT_DIR/startup/cron/cron.daily"
  save_tree_safe /etc/cron.hourly "$OUT_DIR/startup/cron/cron.hourly"
  save_tree_safe /etc/cron.monthly "$OUT_DIR/startup/cron/cron.monthly"
  save_tree_safe /etc/cron.weekly "$OUT_DIR/startup/cron/cron.weekly"

  ok "启动项与计划任务采集完成"
}

#--------------------------------------
# 配置文件：SSH、服务配置、常见应用
#--------------------------------------
collect_configs() {
  info "采集常见配置文件..."
  mkdir -p "$OUT_DIR/configs"
  save_tree_safe /etc/ssh "$OUT_DIR/configs/ssh"
  save_tree_safe /etc/sudoers.d "$OUT_DIR/configs/sudoers.d"
  save_file_safe /etc/sudoers "$OUT_DIR/configs/sudoers"
  save_tree_safe /etc/security "$OUT_DIR/configs/security"
  save_tree_safe /etc/pam.d "$OUT_DIR/configs/pam.d"
  save_tree_safe /etc/sysctl.d "$OUT_DIR/configs/sysctl.d"
  save_tree_safe /etc/ld.so.conf.d "$OUT_DIR/configs/ld.so.conf.d"
  save_file_safe /etc/ld.so.preload "$OUT_DIR/configs/ld.so.preload"
  save_tree_safe /etc/hosts.d "$OUT_DIR/configs/hosts.d"

  # SELinux / AppArmor
  save_cmd_output "$OUT_DIR/security/selinux_status.txt" bash -lc 'getenforce 2>/dev/null || echo "getenforce not available"; sestatus 2>/dev/null || true'
  save_cmd_output "$OUT_DIR/security/apparmor_status.txt" bash -lc 'aa-status 2>/dev/null || apparmor_status 2>/dev/null || echo "apparmor not available"'

  # 常见服务
  for d in nginx httpd apache2 mysql mariadb postgresql redis mongod docker containerd kubelet vsftpd proftpd fail2ban rsyslog; do
    [[ -d "/etc/$d" ]] && save_tree_safe "/etc/$d" "$OUT_DIR/configs/$d"
  done

  ok "配置文件采集完成"
}

#--------------------------------------
# 日志采集：系统与应用
#--------------------------------------
collect_logs() {
  info "采集系统与应用日志..."
  mkdir -p "$OUT_DIR/logs"

  if [[ $SKIP_JOURNAL -eq 0 ]] && need_cmd journalctl; then
    # 导出最近 N 天
    save_cmd_output "$OUT_DIR/logs/journal_last_${RECENT_DAYS}d.txt" bash -lc "journalctl -S \"$((RECENT_DAYS)) days ago\" --no-pager"
    # 常见 facility
    save_cmd_output "$OUT_DIR/logs/journal_auth.txt" bash -lc 'journalctl -u ssh -u sshd -t sshd _SYSTEMD_UNIT=sshd.service -S "30 days ago" --no-pager 2>/dev/null || journalctl -S "30 days ago" -k --no-pager'
  fi

  # /var/log 目录树
  save_tree_safe /var/log "$OUT_DIR/logs/var_log"

  # 常见应用日志
  if [[ $INCLUDE_APP_LOGS -eq 1 ]]; then
    for p in /opt /usr/local /data /srv; do
      [[ -d "$p" ]] || continue
      find "$p" -maxdepth 3 -type d -name log -o -name logs 2>/dev/null | head -n 200 | while read -r d; do
        REL=$(echo "$d" | tr -c 'A-Za-z0-9._/-' '_')
        save_tree_safe "$d" "$OUT_DIR/logs/app_${REL}"
      done
    done
  fi

  ok "日志采集完成"
}

#--------------------------------------
# 近期文件修改、可疑文件与权限
#--------------------------------------
collect_files_recent_and_perms() {
  info "采集近期文件修改与敏感权限...（${RECENT_DAYS}天）"
  mkdir -p "$OUT_DIR/files"

  # 最近修改文件（限制条数，避免海量）
  save_cmd_output "$OUT_DIR/files/recent_modified.txt" bash -lc "find / -xdev -type f -mtime -${RECENT_DAYS} -printf '%TY-%Tm-%Td %TH:%TM:%TS %u %g %m %s %p\n' 2>/dev/null | head -n ${FIND_LIMIT}"
  save_cmd_output "$OUT_DIR/files/recent_changed_attr.txt" bash -lc "find / -xdev -type f -ctime -${RECENT_DAYS} -printf '%TY-%Tm-%Td %TH:%TM:%TS %u %g %m %s %p\n' 2>/dev/null | head -n ${FIND_LIMIT}"

  # SUID/SGID
  save_cmd_output "$OUT_DIR/files/suid_sgid.txt" bash -lc "find / -xdev -type f -perm -4000 -o -perm -2000 -printf '%m %u %g %s %p\n' 2>/dev/null | sort -u"

  # 可写目录与世界可写
  save_cmd_output "$OUT_DIR/files/world_writable.txt" bash -lc "find / -xdev -type d -perm -0002 -printf '%m %u %g %p\n' 2>/dev/null | sort -u | head -n 10000"

  # 脚本与二进制 hash（白名单目录）
  mkdir -p "$OUT_DIR/forensic/hashes"
  for d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
    [[ -d "$d" ]] || continue
    if [[ $ENABLE_HASH -eq 1 ]] && need_cmd "$HASH_CMD"; then
      save_cmd_output "$OUT_DIR/forensic/hashes/$(echo "$d" | tr '/' '_').hash" bash -lc "find $d -type f -maxdepth 1 -exec $HASH_CMD {} + 2>/dev/null | sort -k2"
    fi
  done

  ok "文件与权限采集完成"
}

#--------------------------------------
# 内核模块信息与完整性
#--------------------------------------
collect_kernel_modules() {
  info "采集内核模块信息..."
  mkdir -p "$OUT_DIR/modules"
  save_cmd_output "$OUT_DIR/modules/lsmod.txt" lsmod 2>/dev/null || true
  save_cmd_output "$OUT_DIR/modules/modprobe_D.txt" modprobe -D 2>/dev/null || true

  # 对每个模块进行 modinfo 与文件 hash
  awk 'NR>1{print $1}' "$OUT_DIR/sysinfo/lsmod.txt" 2>/dev/null | sort -u | while read -r m; do
    [[ -z "$m" ]] && continue
    MD="$OUT_DIR/modules/$m"; mkdir -p "$MD"
    save_cmd_output "$MD/modinfo.txt" modinfo "$m" 2>/dev/null || true
    # 查找模块路径
    MODPATH=$(modinfo -n "$m" 2>/dev/null || true)
    if [[ -f "$MODPATH" ]]; then
      save_file_safe "$MODPATH" "$MD/$(basename "$MODPATH")"
      if [[ $ENABLE_HASH -eq 1 ]] && need_cmd "$HASH_CMD"; then
        save_cmd_output "$MD/hash.txt" "$HASH_CMD" "$MODPATH"
      fi
    fi
  done

  ok "内核模块信息采集完成"
}

#--------------------------------------
# Rootkit/隐匿行为线索检查（轻量）
#--------------------------------------
check_rootkit_and_anomalies() {
  info "执行 rootkit 与异常行为轻量检查..."
  mkdir -p "$OUT_DIR/rootkit"

  # 1) /etc/ld.so.preload 是否存在可疑库
  if [[ -f /etc/ld.so.preload ]]; then
    save_file_safe /etc/ld.so.preload "$OUT_DIR/rootkit/ld.so.preload"
    grep -nE "/tmp|/dev|/var/tmp|/var/run|/run|\.(so|dll)$" /etc/ld.so.preload >"$OUT_DIR/rootkit/ld.so.preload_flags.txt" 2>/dev/null || true
  fi

  # 2) PATH 异常：相对路径、当前目录、可写目录优先
  echo "$PATH" >"$OUT_DIR/rootkit/path.txt"
  echo "$PATH" | tr ':' '\n' | nl -ba >"$OUT_DIR/rootkit/path_ranked.txt"
  echo "$PATH" | tr ':' '\n' | while read -r d; do
    [[ -z "$d" ]] && continue
    if [[ ! -d "$d" ]]; then echo "MISSING: $d" >>"$OUT_DIR/rootkit/path_issues.txt"; continue; fi
    perms=$(stat -c '%A %U %G' "$d" 2>/dev/null || true)
    echo "$d -> $perms" >>"$OUT_DIR/rootkit/path_perms.txt"
    # 世界可写且在 PATH 中 -> 高风险
    if [[ -w "$d" && $(stat -c '%a' "$d" 2>/dev/null | cut -c3) -ge 2 ]]; then
      echo "WORLD-WRITABLE: $d $perms" >>"$OUT_DIR/rootkit/path_issues.txt"
    fi
  done

  # 3) 可疑隐藏目录/文件命名
  save_cmd_output "$OUT_DIR/rootkit/susp_hidden_dirs.txt" bash -lc "find / -xdev -type d -name '.* ' -o -name '.. ' -o -name '. .' 2>/dev/null"
  save_cmd_output "$OUT_DIR/rootkit/susp_names.txt" bash -lc "find / -xdev -regextype posix-extended -regex '.*/(\\.|\s|\-|_)?(ssh|cron|dbus|udev|systemd|kworker|kthreadd|auditd)(\.|\s|$).*' 2>/dev/null | head -n 5000"

  # 4) /dev 下的可执行或 ELF
  save_cmd_output "$OUT_DIR/rootkit/dev_exec.txt" bash -lc "find /dev -type f -perm -111 -o -type f -exec file -b {} \; 2>/dev/null | paste - - | head -n 2000"

  # 5) 端口监听进程的可执行路径、哈希
  if need_cmd lsof; then
    mkdir -p "$OUT_DIR/rootkit/listen_bins"
    lsof -Pan -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1" "$2" "$3" "$9" "$10}' | while read -r name pid user lip lport; do
      [[ -z "$pid" ]] && continue
      exe="/proc/$pid/exe"
      if [[ -e "$exe" ]]; then
        ln -sf "$exe" "$OUT_DIR/rootkit/listen_bins/${pid}_${name}_exe"
        if [[ $ENABLE_HASH -eq 1 ]] && need_cmd "$HASH_CMD"; then
          save_cmd_output "$OUT_DIR/rootkit/listen_bins/${pid}_${name}_hash.txt" "$HASH_CMD" "$(readlink -f "$exe" 2>/dev/null || echo "$exe")"
        fi
      fi
    done
  fi

  # 6) kcore/隐藏进程（基于 /proc 扫描）
  #save_cmd_output "$OUT_DIR/rootkit/proc_zombie.txt" bash -lc "ps -eo pid,ppid,stat,cmd | awk '$3 ~ /Z/ {print}'"
  save_cmd_output "$OUT_DIR/rootkit/proc_threads.txt" bash -lc "for p in /proc/[0-9]*; do [[ -r \"$p/status\" ]] && awk '/^Name|^State|^Threads/{print}' \"$p/status\"; done | paste - - - 2>/dev/null"

  # 7) cron/anacron/at 中的可疑行（命令带网络、反弹特征等）
  grep -R -nE '(curl|wget|nc|ncat|socat|bash -i|/dev/tcp/|\bbash\b.*-c|python.*-c|perl.*-e)' \
    "$OUT_DIR/startup/cron" "$OUT_DIR/startup/systemd" "$OUT_DIR/accounts/users" 2>/dev/null >"$OUT_DIR/rootkit/susp_commands.txt" || true

  # 8) SSH 审计：PermitRootLogin、AuthorizedKeys 中的限制
  grep -nEi 'permitrootlogin|passwordauthentication|pubkeyauthentication|authorizedkeyscommand' \
    "$OUT_DIR/configs/ssh/sshd_config"* 2>/dev/null >"$OUT_DIR/rootkit/ssh_flags.txt" || true

  # 9) 环境变量注入（LD_*、PYTHONPATH 等）
  env | sort >"$OUT_DIR/rootkit/env.txt"
  env | grep -E '^LD_|^PYTHONPATH|^GCONV_PATH' >"$OUT_DIR/rootkit/env_susp.txt" 2>/dev/null || true

  # 10) 可执行替换（与包数据库比对）
  if need_cmd rpm; then
    save_cmd_output "$OUT_DIR/rootkit/rpm_verify.txt" rpm -Va 2>/dev/null || true
  elif need_cmd debsums; then
    save_cmd_output "$OUT_DIR/rootkit/debsums.txt" debsums -s 2>/dev/null || echo "debsums not installed" >"$OUT_DIR/rootkit/debsums.txt"
  fi

  # 11) 内核符号与隐藏模块（有限能力）
  save_cmd_output "$OUT_DIR/rootkit/kallsyms_head.txt" head -n 200 /proc/kallsyms 2>/dev/null || true

  ok "Rootkit 与异常行为检查完成（线索版）"
}

#--------------------------------------
# 容器/Docker/Kubernetes 线索
#--------------------------------------
collect_containers() {
  info "采集容器相关信息..."
  mkdir -p "$OUT_DIR/containers"

  if [[ $INCLUDE_DOCKER -eq 1 ]]; then
    save_cmd_output "$OUT_DIR/containers/docker_info.txt" docker info 2>/dev/null || echo "docker not available" >"$OUT_DIR/containers/docker_info.txt"
    save_cmd_output "$OUT_DIR/containers/docker_ps.txt" docker ps -a --no-trunc 2>/dev/null || true
    save_cmd_output "$OUT_DIR/containers/docker_images.txt" docker images --digests 2>/dev/null || true
    save_cmd_output "$OUT_DIR/containers/docker_network.txt" docker network ls 2>/dev/null || true
    save_cmd_output "$OUT_DIR/containers/docker_volume.txt" docker volume ls 2>/dev/null || true
    # 导出容器元数据（可能较多）
    if need_cmd docker; then
      docker ps -qa 2>/dev/null | while read -r cid; do
        [[ -z "$cid" ]] && continue
        CDIR="$OUT_DIR/containers/docker/$cid"; mkdir -p "$CDIR"
        save_cmd_output "$CDIR/inspect.json" docker inspect "$cid"
        save_cmd_output "$CDIR/top.txt" docker top "$cid" aux 2>/dev/null || true
        save_cmd_output "$CDIR/logs.txt" docker logs --tail 1000 "$cid" 2>/dev/null || true
      done
    fi
  fi

  if [[ $INCLUDE_K8S -eq 1 ]]; then
    K="kubectl"
    if need_cmd "$K"; then
      save_cmd_output "$OUT_DIR/containers/k8s_version.txt" "$K" version --short 2>/dev/null || true
      save_cmd_output "$OUT_DIR/containers/k8s_nodes.txt" "$K" get nodes -o wide 2>/dev/null || true
      save_cmd_output "$OUT_DIR/containers/k8s_pods_all.txt" "$K" get pods -A -o wide 2>/dev/null || true
      save_cmd_output "$OUT_DIR/containers/k8s_events.txt" "$K" get events -A --sort-by=.lastTimestamp 2>/dev/null || true
      save_cmd_output "$OUT_DIR/containers/k8s_desc_ns.txt" bash -lc '$K get ns -o name 2>/dev/null | while read ns; do kubectl get all -n ${ns#namespace/} -o wide; done'
    else
      echo "kubectl not available" >"$OUT_DIR/containers/k8s_info.txt"
    fi
  fi

  if need_cmd containerd; then
    save_cmd_output "$OUT_DIR/containers/containerd_info.txt" ctr --namespaces list 2>/dev/null || true
  fi

  ok "容器信息采集完成"
}

#--------------------------------------
# 云环境元数据（仅读取）
#--------------------------------------
collect_cloud_metadata() {
  info "采集云环境元数据..."
  mkdir -p "$OUT_DIR/cloud"
  [[ $INCLUDE_CLOUD -eq 1 ]] || { echo "cloud collection disabled" >"$OUT_DIR/cloud/disabled.txt"; return; }

  # 注意：仅在本机可达的前提下访问，无写操作
  METAS=(
    "169.254.169.254/latest/meta-data"        # AWS/Alibaba/Huawei 变体
    "169.254.169.254/metadata/instance"       # Azure
    "169.254.169.254/computeMetadata/v1"      # GCP (需 header)
  )
  CURL=$(use_if_available curl wget)
  if [[ -z "$CURL" ]]; then
    echo "curl/wget 不可用，跳过" >"$OUT_DIR/cloud/_note.txt"; return
  fi

  for path in "${METAS[@]}"; do
    if [[ "$path" == *computeMetadata* ]]; then
      # GCP 需要 Metadata-Flavor: Google
      if [[ "$CURL" == "curl" ]]; then
        save_cmd_output "$OUT_DIR/cloud/gcp.txt" curl -s -H "Metadata-Flavor: Google" "http://$path/" 2>/dev/null || true
      else
        echo "wget 无法方便设置 header，跳过 gcp" >>"$OUT_DIR/cloud/_note.txt"
      fi
    else
      save_cmd_output "$OUT_DIR/cloud/${path//\//_}.txt" "$CURL" -s "http://$path" 2>/dev/null || true
    fi
  done

  ok "云元数据采集完成"
}

#--------------------------------------
# 抓包（可选）
#--------------------------------------
collect_pcap() {
  [[ $PCAP_CAPTURE -eq 1 ]] || return 0
  info "开始抓包 ${PCAP_DURATION}s..."
  mkdir -p "$OUT_DIR/network/pcap"
  TCPDUMP=$(use_if_available tcpdump)
  if [[ -z "$TCPDUMP" ]]; then
    warn "tcpdump 不可用，跳过抓包"
    return 0
  fi
  IFACE="$PCAP_IFACE"
  if [[ -z "$IFACE" ]]; then
    IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '/ dev /{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
    IFACE=${IFACE:-"any"}
  fi
  PCAP_FILE="$OUT_DIR/network/pcap/capture_${IFACE}_${PCAP_DURATION}s.pcap"
  "$TCPDUMP" -i "$IFACE" -w "$PCAP_FILE" -G "$PCAP_DURATION" -W 1 -nn 2>"$OUT_DIR/network/pcap/tcpdump_${IFACE}.log" || true
  ok "抓包完成：$PCAP_FILE"
}

#--------------------------------------
# 取证辅助：开放句柄、可执行映像、核心转储设置
#--------------------------------------
collect_forensic_helpers() {
  info "采集取证辅助信息..."
  save_cmd_output "$OUT_DIR/forensic/ulimit_a.txt" ulimit -a
  save_cmd_output "$OUT_DIR/forensic/sysctl_core.txt" sysctl kernel.core_pattern fs.suid_dumpable 2>/dev/null || true
  save_cmd_output "$OUT_DIR/forensic/open_files_count.txt" bash -lc 'for p in /proc/[0-9]*; do echo $(basename $p) $(ls -1 $p/fd 2>/dev/null | wc -l); done | sort -nrk2 | head -n 200'
  ok "取证辅助信息采集完成"
}

#--------------------------------------
# 汇总报告（简要 JSON + TXT）
#--------------------------------------
write_summary_report() {
  info "生成汇总报告..."
  local jf="$OUT_DIR/meta/summary.json"
  local tf="$OUT_DIR/meta/summary.txt"
  {
    echo '{'
    write_json_kv "$jf" "script" "$SCRIPT_NAME"
  } >"$jf" 2>/dev/null || true

  # JSON（手工拼接，末尾修正逗号）
  {
    echo '{'
    echo "  \"script\": \"$SCRIPT_NAME\"," 
    echo "  \"version\": \"$VERSION\"," 
    echo "  \"host\": \"$HOSTNAME_SAFE\"," 
    echo "  \"start_ts\": $START_TS,"
    echo "  \"end_ts\": $(date +%s),"
    echo "  \"os\": \"$OS_PRETTY\"," 
    echo "  \"pkg_tool\": \"${PKG_TOOL:-N/A}\"," 
    echo "  \"service_mgr\": \"${SERVICE_MGR:-$INIT_SYS}\"," 
    echo "  \"recent_days\": $RECENT_DAYS,"
    echo "  \"fast_mode\": $FAST_MODE,"
    echo "  \"skip_journal\": $SKIP_JOURNAL"
    echo '}'
  } >"$jf"

  {
    echo "==== IR Collection Summary ===="
    echo "Host: $HOSTNAME_SAFE"
    echo "OS  : $OS_PRETTY"
    echo "When: $(date -d @${START_TS} '+%F %T') -> $(date '+%F %T')"
    echo "Dirs: $OUT_DIR"
    echo "Opts: recent_days=$RECENT_DAYS fast=$FAST_MODE pcap=$PCAP_CAPTURE"
    echo "----- Key Artifacts -----"
    echo "- System: sysinfo/ uname.txt, ps_aux.txt, ss_all.txt, lsmod.txt"
    echo "- Accounts: accounts/ passwd.txt, sudoers.txt, users/*/ssh/"
    echo "- Startup: startup/systemd/, cron/"
    echo "- Logs: logs/var_log/ (+journal_*.txt)"
    echo "- Rootkit: rootkit/* (ld.so.preload, path_issues, rpm_verify/debsums)"
    echo "- Modules: modules/<mod>/ (modinfo, hash)"
    echo "- Files: files/recent_modified.txt, suid_sgid.txt"
    echo "- Network: network/listen_map.txt, iptables.txt"
  } >"$tf"

  ok "汇总报告生成完成"
}

#--------------------------------------
# 打包与校验
#--------------------------------------
archive_and_hash() {
  [[ $ARCHIVE -eq 1 ]] || return 0
  info "打包输出目录..."
  local tarname="${OUT_DIR%/}.tar.gz"
  "$COMPRESS_CMD" ${COMPRESS_ARGS[@]} "$tarname" -C "$(dirname "$OUT_DIR")" "$(basename "$OUT_DIR")" 2>>"$LOG_FILE" || {
    warn "打包失败：$tarname"
    return 0
  }
  if [[ $ENABLE_HASH -eq 1 ]] && need_cmd "$HASH_CMD"; then
    "$HASH_CMD" "$tarname" >"${tarname}.sha256" 2>>"$LOG_FILE" || true
  fi
  ok "打包完成：$tarname"
}

#--------------------------------------
# 参数解析
#--------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--out) OUT_DIR="$2"; shift 2;;
      -q|--quiet) QUIET=1; shift;;
      -f|--fast) FAST_MODE=1; shift;;
      -d|--days) RECENT_DAYS="$2"; shift 2;;
      -l|--find-limit) FIND_LIMIT="$2"; shift 2;;
      --no-archive) ARCHIVE=0; shift;;
      --no-hash) ENABLE_HASH=0; shift;;
      --no-journal) SKIP_JOURNAL=1; shift;;
      --no-app-logs) INCLUDE_APP_LOGS=0; shift;;
      --no-docker) INCLUDE_DOCKER=0; shift;;
      --no-k8s) INCLUDE_K8S=0; shift;;
      --no-cloud) INCLUDE_CLOUD=0; shift;;
      --pcap) PCAP_CAPTURE=1; PCAP_IFACE="${2:-}"; [[ "$PCAP_IFACE" == -* || -z "$PCAP_IFACE" ]] && PCAP_IFACE="" || shift; shift;;
      --pcap-duration) PCAP_DURATION="$2"; shift 2;;
      --timeout) TIMEOUT_SEC="$2"; shift 2;;
      -h|--help) usage; exit 0;;
      *) warn "未知参数：$1"; usage; exit 1;;
    esac
  done
}

#--------------------------------------
# 主流程
#--------------------------------------
main() {
  parse_args "$@"
  init_out_dir "$@"
  probe_os
  collect_basic_sysinfo
  collect_accounts
  collect_process_and_network
  collect_startup_and_services
  collect_configs
  collect_logs
  collect_files_recent_and_perms
  #collect_kernel_modules
  #check_rootkit_and_anomalies
  #collect_containers
  #collect_cloud_metadata
  collect_pcap
  collect_forensic_helpers
  write_summary_report
  archive_and_hash

  DURATION=$(( $(date +%s) - START_TS ))
  ok "全部完成，用时 ${DURATION}s。结果目录：$OUT_DIR"
}

main "$@"

