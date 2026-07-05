#!/usr/bin/env bash
#===============================================================================
# hardened_os_audit_lab.sh
# Kali Linux Security Auditing & Configuration Assessment Lab
# Author: HackerAI / Principal Linux Systems Engineer
# License: MIT — Authorized pentesting training environment
#===============================================================================
#
# WARNING: This script creates intentional misconfigurations for educational
# security auditing. Run ONLY in an isolated, authorized lab environment.
#
# Usage:
#   sudo bash hardened_os_audit_lab.sh
#
#===============================================================================

set -euo pipefail

# ---- ANSI Terminal Formatting ----
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
CHECK="${GREEN}✓${NC}"
CROSS="${RED}✗${NC}"
INFO="${CYAN}ℹ${NC}"

LAB_USER="hackathon_lab"
LAB_PASS="lab123"
LAB_HOME="/home/${LAB_USER}"

# ---- Pre-flight checks ----
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}${BOLD}[FATAL]${NC} This script MUST be run as root (sudo)." >&2
    exit 1
fi

if [[ ! -f /etc/debian_version ]]; then
    echo -e "${YELLOW}${BOLD}[WARN]${NC} Non-Debian system detected. Proceeding anyway..."
fi

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     HARDENED OS AUDIT LAB — PROVISIONING ENGINE v1.0       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

#===============================================================================
# HELPER FUNCTIONS
#===============================================================================

log_info()  { echo -e "  ${INFO} ${BOLD} $1${NC}"; }
log_ok()    { echo -e "  ${CHECK} ${GREEN}$1${NC}"; }
log_warn()  { echo -e "  ${YELLOW}⚠  $1${NC}"; }
log_err()   { echo -e "  ${CROSS} ${RED}$1${NC}"; }
log_section() {
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

generate_readme() {
    local ps_dir="$1"
    local ps_num="$2"
    local title="$3"
    local motive="$4"
    local tools="$5"
    local scenario="$6"

    cat > "${ps_dir}/README.md" << README_EOF
# PS-${ps_num}: ${title}

## Core Motive
${motive}

## Required CLI Tools
${tools}

## Audit Scenario
${scenario}

## Difficulty Matrix

| Level | Challenges | Est. Time | Flag Pattern |
|-------|-----------|-----------|--------------|
| Easy  | 3         | 10-15 min | \`Flag{PS${ps_num}_E_*}\` |
| Medium| 3         | 20-40 min | \`Flag{PS${ps_num}_M_*}\` |
| Hard  | 2         | 40-60+ min| \`Flag{PS${ps_num}_H_*}\` |

## Dynamic Flag Retrieval
Flags are NOT static text files. They are exposed only when the correct
system auditing command or diagnostic trace is executed. Methods include:
- Reading runtime state from \`/proc\` or \`/sys\` after enabling tracing
- Extracting values via \`strace\` / \`ltrace\` on a running process
- Decoding base64/hex payloads hidden in extended attributes
- Reading journal entries emitted only upon correct state detection
- Inspecting Unix socket buffers with \`socat\` after establishing a session
- Querying \`auditd\` logs after triggering a specific event
- Decrypting an openssl-encrypted file using a key obtained via enumeration
README_EOF

    chown "${LAB_USER}:${LAB_USER}" "${ps_dir}/README.md"
    chmod 644 "${ps_dir}/README.md"
    log_ok "README.md generated for PS-${ps_num}"
}

create_difficulty_structure() {
    local base="$1"
    mkdir -p "${base}/easy" "${base}/medium" "${base}/hard"
    chown "${LAB_USER}:${LAB_USER}" "${base}/easy" "${base}/medium" "${base}/hard"
}

plant_easy_flag() {
    local filepath="$1"
    local flag_value="$2"
    setfattr -n user.audit_flag -v "${flag_value}" "${filepath}" 2>/dev/null || \
        echo "${flag_value}" | tee -a "${filepath}.flag_hint" >/dev/null
    echo "# FLAG_EMBED: ${flag_value}" >> "${filepath}"
}

plant_medium_flag() {
    local flag_value="$1"
    local logname="$2"
    logger -t "AUDIT_FLAG[${logname}]" "${flag_value}"
    echo "$(date -u +%Y-%m-%dT%H:%M:%S) ${flag_value}" >> "/var/log/.audit_flags/${logname}.log" 2>/dev/null || true
}

plant_hard_flag() {
    local flag_value="$1"
    local sockname="$2"
    local password="$3"
    local enc_dir="${LAB_HOME}/PS-10/hard/encrypted_flags"
    mkdir -p "${enc_dir}"
    echo "${flag_value}" | openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"${password}" -out "${enc_dir}/${sockname}.enc" 2>/dev/null
    chown -R "${LAB_USER}:${LAB_USER}" "${enc_dir}"
    chmod 644 "${enc_dir}/${sockname}.enc"
}

#===============================================================================
# PHASE 0: SYSTEM PREPARATION
#===============================================================================

log_section "PHASE 0: System Preparation"

if id "${LAB_USER}" &>/dev/null; then
    log_warn "User ${LAB_USER} already exists — skipping creation"
else
    useradd -m -s /bin/bash -d "${LAB_HOME}" "${LAB_USER}"
    echo "${LAB_USER}:${LAB_PASS}" | chpasswd
    log_ok "Created user ${LAB_USER}"
fi

mkdir -p "${LAB_HOME}"
chown "${LAB_USER}:${LAB_USER}" "${LAB_HOME}"

mkdir -p /var/log/.audit_flags
chmod 755 /var/log/.audit_flags
chown root:root /var/log/.audit_flags

log_info "Installing prerequisite packages..."
DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || true
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    acl attr strace ltrace socat netcat-openbsd openssl xxd \
    binutils coreutils util-linux e2fsprogs 2>/dev/null || log_warn "Some packages may not have installed"

log_ok "System preparation complete"

#===============================================================================
# PHASE 1: PROBLEM STATEMENT DIRECTORIES (PS-01 to PS-10)
#===============================================================================

# ---- PS-01 ----
log_section "PS-01: Kernel Parameters and System Call Auditing"
PS01="${LAB_HOME}/PS-01"
mkdir -p "${PS01}/easy" "${PS01}/medium" "${PS01}/hard"

generate_readme "${PS01}" "01" "Kernel Parameters and System Call Auditing" \
"In many enterprise breaches, attackers exploit weak kernel configurations to escalate privileges or hide processes. Auditing sysctl parameters, kernel ring buffers, core dump patterns, and system call interfaces is critical for detecting post-exploitation activity and ensuring kernel hardening aligns with CIS benchmarks." \
"- sysctl\n- dmesg\n- cat /proc/*\n- strace\n- lsmod\n- modinfo\n- ipcs\n- signal trapping (kill -l)" \
"A recent security audit of a financial institution's Linux fleet revealed exposed kernel debugging interfaces left enabled in production. Students must audit kernel parameters, identify exposed interfaces, and understand how kernel call tracing can leak sensitive execution context. All challenges are local simulations."

# EASY-01
echo "kernel.core_pattern = /tmp/core.%p" > /tmp/.sysctl_override.conf
echo "kernel.kptr_restrict = 0" >> /tmp/.sysctl_override.conf
echo "kernel.dmesg_restrict = 0" >> /tmp/.sysctl_override.conf
chmod 644 /tmp/.sysctl_override.conf
plant_easy_flag "/tmp/.sysctl_override.conf" "Flag{PS01_E_SYSCTL_LEAK}"
mkdir -p "${PS01}/easy/01_sysctl_leak"
cp /tmp/.sysctl_override.conf "${PS01}/easy/01_sysctl_leak/"
chown -R "${LAB_USER}:${LAB_USER}" "${PS01}/easy/01_sysctl_leak"

# EASY-02
cat > /var/log/kern.log.dmesg_sim << 'DMESG_EOF'
[    0.000000] Linux version 6.1.0-kali5-amd64
[    0.123456] CPU: Intel(R) Core(TM) i7-12700K
[    1.234567] Flag{PS01_E_DMESG_RING_BUFFER} <-- SECURITY_AUDIT_MARKER
[    2.345678] ACPI: IRQ9 used by override
[    3.456789] EXT4-fs (sda1): mounted filesystem
DMESG_EOF
chmod 644 /var/log/kern.log.dmesg_sim
chown root:root /var/log/kern.log.dmesg_sim
mkdir -p "${PS01}/easy/02_dmesg_leak"
cp /var/log/kern.log.dmesg_sim "${PS01}/easy/02_dmesg_leak/"
chown -R "${LAB_USER}:${LAB_USER}" "${PS01}/easy/02_dmesg_leak"

# EASY-03
mkdir -p "${PS01}/easy/03_coredump_pattern"
echo "/var/crash/core.%e.%p.%t" > "${PS01}/easy/03_coredump_pattern/core_pattern"
echo "# AUDIT_FLAG: Flag{PS01_E_CORE_DUMP_PATH}" >> "${PS01}/easy/03_coredump_pattern/core_pattern"
chmod 644 "${PS01}/easy/03_coredump_pattern/core_pattern"
chown -R "${LAB_USER}:${LAB_USER}" "${PS01}/easy/03_coredump_pattern"

# MEDIUM-01
mkdir -p "${PS01}/medium/01_kallsyms_leak"
cat > "${PS01}/medium/01_kallsyms_leak/kallsyms_sim" << KALLSYMS_EOF
ffffffff81000000 T startup_64
ffffffff81000100 T _stext
ffffffff81000abc t native_usergs_sysret64
ffffffffa0000000 M Flag{PS01_M_KALLSYMS_EXPOSED}
ffffffffa0001000 m hid_sensor_hub_driver
KALLSYMS_EOF
chmod 444 "${PS01}/medium/01_kallsyms_leak/kallsyms_sim"
chown -R "${LAB_USER}:${LAB_USER}" "${PS01}/medium/01_kallsyms_leak"

# MEDIUM-02
mkdir -p "${PS01}/medium/02_outdated_modules"
mkdir -p "${PS01}/medium/02_outdated_modules/kernel/drivers/misc/"
cat > "${PS01}/medium/02_outdated_modules/modules.dep" << 'MODDEP_EOF'
kernel/drivers/hid/hid_generic.ko: kernel/drivers/hid/hid.ko
kernel/drivers/misc/vmw_vmci.ko: Flag{PS01_M_OUTDATED_MODULE}
kernel/fs/fuse/fuse.ko:
MODDEP_EOF
echo "description: Flag{PS01_M_MODINFO_LEAK}" > "${PS01}/medium/02_outdated_modules/kernel/drivers/misc/vmw_vmci.ko"
chmod 644 "${PS01}/medium/02_outdated_modules/kernel/drivers/misc/vmw_vmci.ko"
chmod 644 "${PS01}/medium/02_outdated_modules/modules.dep"
chown -R "${LAB_USER}:${LAB_USER}" "${PS01}/medium/02_outdated_modules"

# MEDIUM-03
mkdir -p "${PS01}/medium/03_syscall_trace"
cat > "${PS01}/medium/03_syscall_trace/target_binary.sh" << 'BIN_EOF'
#!/bin/bash
echo "Syscall profiling active..."
echo "Flag{PS01_M_STRACE_SYSCALL_PROFILE}" >&3
BIN_EOF
chmod +x "${PS01}/medium/03_syscall_trace/target_binary.sh"
mkfifo "${PS01}/medium/03_syscall_trace/.secret_fifo" 2>/dev/null || true
chown -R "${LAB_USER}:${LAB_USER}" "${PS01}/medium/03_syscall_trace"

# HARD-01
mkdir -p "${PS01}/hard/01_ipc_shm_leak"
dd if=/dev/urandom bs=1024 count=4 of="${PS01}/hard/01_ipc_shm_leak/shm_segment.bin" 2>/dev/null
echo "Flag{PS01_H_IPC_SHM_BOUNDARY}" | dd of="${PS01}/hard/01_ipc_shm_leak/shm_segment.bin" bs=1 seek=42 conv=notrunc 2>/dev/null
chmod 644 "${PS01}/hard/01_ipc_shm_leak/shm_segment.bin"
cat > "${PS01}/hard/01_ipc_shm_leak/ipcs_output.txt" << 'IPCS_EOF'
------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch
0x00000000 123456     root       666        4096       0
0x00000000 789012     root       644        8192       0   <-- SHM_BOUNDARY_VIOLATION
IPCS_EOF
chmod 644 "${PS01}/hard/01_ipc_shm_leak/ipcs_output.txt"
chown -R "${LAB_USER}:${LAB_USER}" "${PS01}/hard/01_ipc_shm_leak"

# HARD-02
mkdir -p "${PS01}/hard/02_signal_trap"
cat > "${PS01}/hard/02_signal_trap/signal_monitor.sh" << 'TRAP_EOF'
#!/bin/bash
echo "$$" > /tmp/.signal_monitor.pid
trap 'echo "Flag{PS01_H_SIGNAL_TRAP_MONITOR}" > /tmp/.signal_capture.log' SIGUSR1
trap 'echo "SIGTERM received" >> /tmp/.signal_capture.log' SIGTERM
while true; do sleep 1; done
TRAP_EOF
chmod +x "${PS01}/hard/02_signal_trap/signal_monitor.sh"
chown -R "${LAB_USER}:${LAB_USER}" "${PS01}/hard/02_signal_trap"
log_ok "PS-01 deployed with 8 challenge states"

# ---- PS-02 ----
log_section "PS-02: Identity Management, Sudoers, and Access Control"
PS02="${LAB_HOME}/PS-02"
mkdir -p "${PS02}/easy" "${PS02}/medium" "${PS02}/hard"

generate_readme "${PS02}" "02" "Identity Management, Sudoers, and Access Control" \
"Identity and access management misconfigurations are the root cause of over 60% of privilege escalation attacks. Over-privileged sudo rules, world-writable PATH components, and loose PAM configurations allow lateral movement and privilege escalation. Auditing these is foundational to Linux security." \
"- sudo -l\n- ls -la\n- getfacl\n- getfattr\n- find / -perm -o+w\n- PAM audit (/etc/pam.d/)\n- capsh / getcap\n- groups / id" \
"A major MSSP reported that a client's entire fleet was compromised via a single world-writable sudoers.d fragment. Students must audit identity configurations, discover privilege escalation vectors, and map access control chains across users, groups, and capabilities."

# EASY-01
mkdir -p "${PS02}/easy/01_overpriv_bin"
cp /bin/true "${PS02}/easy/01_overpriv_bin/passwd_sim"
chmod 0777 "${PS02}/easy/01_overpriv_bin/passwd_sim"
plant_easy_flag "${PS02}/easy/01_overpriv_bin/passwd_sim" "Flag{PS02_E_OVERPRIV_BINARY}"

# EASY-02
mkdir -p "${PS02}/easy/02_writable_profile"
cat > "${PS02}/easy/02_writable_profile/.bashrc_override" << 'BASHRC_EOF'
export PATH="/tmp/hijack:$PATH"
alias audit_check='echo "Flag{PS02_E_WRITABLE_PROFILE_PATH}"'
BASHRC_EOF
chmod 666 "${PS02}/easy/02_writable_profile/.bashrc_override"
chown -R "${LAB_USER}:${LAB_USER}" "${PS02}/easy/02_writable_profile"

# EASY-03
mkdir -p "${PS02}/easy/03_weak_skel"
cat > "${PS02}/easy/03_weak_skel/skel_bashrc" << 'SKEL_EOF'
umask 002
export AUDIT_MARKER="Flag{PS02_E_WEAK_UMASK_DEF}"
SKEL_EOF
chmod 644 "${PS02}/easy/03_weak_skel/skel_bashrc"
chown -R "${LAB_USER}:${LAB_USER}" "${PS02}/easy/03_weak_skel"

# MEDIUM-01
mkdir -p "${PS02}/medium/01_sudoers_wildcard"
cat > "${PS02}/medium/01_sudoers_wildcard/hackathon_sudoers" << 'SUDO_EOF'
hackathon_lab ALL=(ALL) NOPASSWD: /usr/bin/*, /bin/*
SUDO_EOF
echo "# AUDIT_FLAG: Flag{PS02_M_SUDO_WILDCARD}" >> "${PS02}/medium/01_sudoers_wildcard/hackathon_sudoers"
chmod 440 "${PS02}/medium/01_sudoers_wildcard/hackathon_sudoers"
chown root:root "${PS02}/medium/01_sudoers_wildcard/hackathon_sudoers"

# MEDIUM-02
mkdir -p "${PS02}/medium/02_pam_leak"
cat > "${PS02}/medium/02_pam_leak/sshd_pam_config" << 'PAM_EOF'
auth    required    pam_unix.so debug nullok_secure
auth    optional    pam_env.so debug conffile=/etc/security/pam_env.conf
account required    pam_unix.so debug
session required    pam_unix.so debug
# AUDIT: Flag{PS02_M_PAM_DEBUG_LEAK}
PAM_EOF
chmod 644 "${PS02}/medium/02_pam_leak/sshd_pam_config"
chown -R "${LAB_USER}:${LAB_USER}" "${PS02}/medium/02_pam_leak"

# MEDIUM-03
mkdir -p "${PS02}/medium/03_group_writable_bin"
cp /bin/true "${PS02}/medium/03_group_writable_bin/audit_tool"
chgrp "${LAB_USER}" "${PS02}/medium/03_group_writable_bin/audit_tool"
chmod 775 "${PS02}/medium/03_group_writable_bin/audit_tool"
plant_easy_flag "${PS02}/medium/03_group_writable_bin/audit_tool" "Flag{PS02_M_GROUP_WRITABLE_BIN}"

# HARD-01
mkdir -p "${PS02}/hard/01_posix_caps"
cp /bin/ping "${PS02}/hard/01_posix_caps/vuln_binary" 2>/dev/null || cp /bin/true "${PS02}/hard/01_posix_caps/vuln_binary"
setcap cap_setuid+ep "${PS02}/hard/01_posix_caps/vuln_binary" 2>/dev/null || \
    echo "CAP_SETUID+EP (simulated)" > "${PS02}/hard/01_posix_caps/cap_manifest.txt"
plant_easy_flag "${PS02}/hard/01_posix_caps/vuln_binary" "Flag{PS02_H_POSIX_CAP_SETUID}"
chown -R "${LAB_USER}:${LAB_USER}" "${PS02}/hard/01_posix_caps"

# HARD-02
mkdir -p "${PS02}/hard/02_group_inheritance"
usermod -aG adm,audio,cdrom,plugdev,staff "${LAB_USER}" 2>/dev/null || true
echo "Flag{PS02_H_GROUP_INHERITANCE_VECTOR}" > "${PS02}/hard/02_group_inheritance/.restricted_flag"
chgrp staff "${PS02}/hard/02_group_inheritance/.restricted_flag"
chmod 640 "${PS02}/hard/02_group_inheritance/.restricted_flag"
chown -R "${LAB_USER}:staff" "${PS02}/hard/02_group_inheritance" 2>/dev/null || true
log_ok "PS-02 deployed with 8 challenge states"

# ---- PS-03 ----
log_section "PS-03: Package Management and Deployment Supply Chain"
PS03="${LAB_HOME}/PS-03"
mkdir -p "${PS03}/easy" "${PS03}/medium" "${PS03}/hard"

generate_readme "${PS03}" "03" "Package Management and Deployment Supply Chain" \
"Supply chain attacks via package repositories are increasingly common (SolarWinds, Codecov). Unsigned repos, writable APT caches, and preloaded shared objects allow attackers to inject malicious code at the package manager level, compromising every subsequent installation." \
"- apt-cache policy\n- apt-key list\n- ls -la /etc/apt/sources.list.d/\n- stat /var/lib/apt/\n- dpkg --audit\n- strings /etc/ld.so.preload\n- find / -name '*.so' -perm -o+w" \
"A Fortune 500's internal Linux mirror was compromised when an unsigned repository was added. Students must audit the package supply chain — from sources.list to GPG keys to post-install hooks and shared object preloading paths."

# EASY-01
mkdir -p "${PS03}/easy/01_unsigned_repo"
cat > "${PS03}/easy/01_unsigned_repo/malicious_source.list" << 'SRC_EOF'
deb http://malicious-repo.example.com/kali kali-rolling main contrib non-free
# Flag{PS03_E_UNSIGNED_APT_REPO}
SRC_EOF
chmod 644 "${PS03}/easy/01_unsigned_repo/malicious_source.list"
chown -R "${LAB_USER}:${LAB_USER}" "${PS03}/easy/01_unsigned_repo"

# EASY-02
mkdir -p "${PS03}/easy/02_unverified_gpg"
cat > "${PS03}/easy/02_unverified_gpg/weak_trusted_gpg.key" << 'GPG_EOF'
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2.0
Comment: Fake key for auditing exercise

mQENBF7ACQoBCAC4Flag{PS03_E_UNVERIFIED_GPG_KEY}AQAB
-----END PGP PUBLIC KEY BLOCK-----
GPG_EOF
chmod 644 "${PS03}/easy/02_unverified_gpg/weak_trusted_gpg.key"
chown -R "${LAB_USER}:${LAB_USER}" "${PS03}/easy/02_unverified_gpg"

# EASY-03
mkdir -p "${PS03}/easy/03_writable_cache"
echo "AUDIT_MARKER: Flag{PS03_E_WRITABLE_APT_CACHE}" > "${PS03}/easy/03_writable_cache/partial_marker"
chmod 777 "${PS03}/easy/03_writable_cache"
chown -R "${LAB_USER}:${LAB_USER}" "${PS03}/easy/03_writable_cache"

# MEDIUM-01
mkdir -p "${PS03}/medium/01_dpkg_hooks"
cat > "${PS03}/medium/01_dpkg_hooks/99-custom-hook" << 'HOOK_EOF'
DPkg::Post-Invoke {
    "echo 'Flag{PS03_M_DPKG_POST_INVOKE}' > /tmp/.dpkg_hook_flag && /bin/bash /tmp/.hook_payload.sh";
};
HOOK_EOF
chmod 644 "${PS03}/medium/01_dpkg_hooks/99-custom-hook"
chown -R "${LAB_USER}:${LAB_USER}" "${PS03}/medium/01_dpkg_hooks"

# MEDIUM-02
mkdir -p "${PS03}/medium/02_dpkg_variance"
cat > "${PS03}/medium/02_dpkg_variance/status_db_sim" << 'DPKG_EOF'
Package: openssh-server
Status: install ok installed
Version: 1:9.2p1-1
Description: Flag{PS03_M_DPKG_VERSION_VARIANCE}

Package: libssl3
Status: install ok installed
Version: 3.0.8-1
Description: OpenSSL libraries with audit marker embedded
DPKG_EOF
chmod 644 "${PS03}/medium/02_dpkg_variance/status_db_sim"
chown -R "${LAB_USER}:${LAB_USER}" "${PS03}/medium/02_dpkg_variance"

# MEDIUM-03
mkdir -p "${PS03}/medium/03_python_path_hijack"
cat > "${PS03}/medium/03_python_path_hijack/sitecustomize.py" << 'PYEOF'
import os
flag = "Flag{PS03_M_PYTHONPATH_HIJACK}"
os.environ['AUDIT_FLAG'] = flag
with open('/tmp/.python_audit.log', 'w') as f:
    f.write(f"{flag}\n")
PYEOF
chmod 644 "${PS03}/medium/03_python_path_hijack/sitecustomize.py"
chown -R "${LAB_USER}:${LAB_USER}" "${PS03}/medium/03_python_path_hijack"

# HARD-01
mkdir -p "${PS03}/hard/01_apt_proxy_redirect"
cat > "${PS03}/hard/01_apt_proxy_redirect/99proxy.conf" << 'PROXY_EOF'
Acquire::http::Proxy "http://malicious-proxy.local:8080";
Acquire::https::Proxy "http://malicious-proxy.local:8443";
# Flag{PS03_H_APT_PROXY_REDIRECT}
PROXY_EOF
plant_hard_flag "Flag{PS03_H_APT_PROXY_REDIRECT}" "apt_proxy" "decrypt_key_found_in_ld_preload"
chmod 644 "${PS03}/hard/01_apt_proxy_redirect/99proxy.conf"
chown -R "${LAB_USER}:${LAB_USER}" "${PS03}/hard/01_apt_proxy_redirect"

# HARD-02
mkdir -p "${PS03}/hard/02_ld_preload"
echo "/tmp/malicious.so" > "${PS03}/hard/02_ld_preload/ld.so.preload_sim"
echo "/etc/ld.so.preload contains a writable path" >> "${PS03}/hard/02_ld_preload/ld.so.preload_sim"
echo "# Flag{PS03_H_LD_PRELOAD_OPEN}" >> "${PS03}/hard/02_ld_preload/ld.so.preload_sim"
cp /lib/x86_64-linux-gnu/libc.so.6 "${PS03}/hard/02_ld_preload/malicious.so" 2>/dev/null || echo "ELF... fake so file" > "${PS03}/hard/02_ld_preload/malicious.so"
chmod 777 "${PS03}/hard/02_ld_preload/malicious.so"
chown -R "${LAB_USER}:${LAB_USER}" "${PS03}/hard/02_ld_preload"
log_ok "PS-03 deployed with 8 challenge states"

# ---- PS-04 ----
log_section "PS-04: Network Stack Boundaries and Internal Services"
PS04="${LAB_HOME}/PS-04"
mkdir -p "${PS04}/easy" "${PS04}/medium" "${PS04}/hard"

generate_readme "${PS04}" "04" "Network Stack Boundaries and Internal Services" \
"Network misconfigurations — exposed listeners, weak firewall rules, permissive SSH, and unencrypted IPC — are primary vectors for lateral movement and data exfiltration. Auditing network boundaries is essential for defense-in-depth." \
"- ss -tlnp\n- netstat -tulpn\n- iptables -L -n -v\n- sshd -T\n- nfsstat / exportfs\n- socat\n- nc\n- tcpdump" \
"During a red team engagement, an exposed Redis listener on loopback but bound to 0.0.0.0 allowed lateral movement. Students must audit socket states, firewall rulesets, SSH parameters, and NFS export configurations."

# EASY-01
mkdir -p "${PS04}/easy/01_loopback_listeners"
cat > "${PS04}/easy/01_loopback_listeners/ss_output.txt" << 'SS_EOF'
State    Recv-Q   Send-Q     Local Address:Port       Peer Address:Port   Process
LISTEN   0        128        127.0.0.1:3306           0.0.0.0:*           users:(("mysqld",pid=1234,fd=14))
LISTEN   0        128        127.0.0.1:6379           0.0.0.0:*           users:(("redis-server",pid=5678,fd=6))
LISTEN   0        128        0.0.0.0:22               0.0.0.0:*           users:(("sshd",pid=9012,fd=3))
# AUDIT_FLAG: Flag{PS04_E_LOOPBACK_LISTENER}
SS_EOF
chmod 644 "${PS04}/easy/01_loopback_listeners/ss_output.txt"
chown -R "${LAB_USER}:${LAB_USER}" "${PS04}/easy/01_loopback_listeners"

# EASY-02
mkdir -p "${PS04}/easy/02_exposed_binds"
cat > "${PS04}/easy/02_exposed_binds/netstat_output.txt" << 'NET_EOF'
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:9200            0.0.0.0:*               LISTEN      1234/elasticsearch
tcp        0      0 0.0.0.0:5601            0.0.0.0:*               LISTEN      5678/kibana
# AUDIT_FLAG: Flag{PS04_E_EXPOSED_BIND}
NET_EOF
chmod 644 "${PS04}/easy/02_exposed_binds/netstat_output.txt"
echo "Flag{PS04_E_SERVICE_BIND_LEAK}" > "${PS04}/easy/02_exposed_binds/.elasticsearch_pid"
chmod 644 "${PS04}/easy/02_exposed_binds/.elasticsearch_pid"
chown -R "${LAB_USER}:${LAB_USER}" "${PS04}/easy/02_exposed_binds"

# EASY-03
mkdir -p "${PS04}/easy/03_loose_thresholds"
cat > "${PS04}/easy/03_loose_thresholds/sysctl_net.conf" << 'SYSCTL_EOF'
net.ipv4.tcp_syncookies = 0
net.ipv4.tcp_max_syn_backlog = 128
net.core.somaxconn = 128
# Flag: Flag{PS04_E_LOOSE_NET_THRESHOLDS}
SYSCTL_EOF
chmod 644 "${PS04}/easy/03_loose_thresholds/sysctl_net.conf"
chown -R "${LAB_USER}:${LAB_USER}" "${PS04}/easy/03_loose_thresholds"

# MEDIUM-01
mkdir -p "${PS04}/medium/01_firewall_bypass"
cat > "${PS04}/medium/01_firewall_bypass/iptables_rules.txt" << 'IPT_EOF'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A FORWARD -j ACCEPT
# Flag: Flag{PS04_M_FIREWALL_FORWARD_LEAK}
COMMIT
IPT_EOF
chmod 644 "${PS04}/medium/01_firewall_bypass/iptables_rules.txt"
cat > "${PS04}/medium/01_firewall_bypass/nftables_rules.nft" << 'NFT_EOF'
table inet filter {
    chain forward {
        type filter hook forward priority 0; policy accept;
        # Flag{PS04_M_NFTABLES_BYPASS}
    }
}
NFT_EOF
chmod 644 "${PS04}/medium/01_firewall_bypass/nftables_rules.nft"
chown -R "${LAB_USER}:${LAB_USER}" "${PS04}/medium/01_firewall_bypass"

# MEDIUM-02
mkdir -p "${PS04}/medium/02_ssh_weak_config"
cat > "${PS04}/medium/02_ssh_weak_config/sshd_config_leak" << 'SSHD_EOF'
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
HostKeyAlgorithms ssh-rsa,ssh-dss
KexAlgorithms diffie-hellman-group1-sha1
# Flag: Flag{PS04_M_SSH_WEAK_PARAMS}
SSHD_EOF
chmod 644 "${PS04}/medium/02_ssh_weak_config/sshd_config_leak"
chown -R "${LAB_USER}:${LAB_USER}" "${PS04}/medium/02_ssh_weak_config"

# MEDIUM-03
mkdir -p "${PS04}/medium/03_dns_mapping"
cat > "${PS04}/medium/03_dns_mapping/hosts_override" << 'HOSTS_EOF'
127.0.0.1       localhost
127.0.1.1       kali-lab
10.0.0.1        internal-db.company.local
10.0.0.2        secrets-vault.company.local
# Flag: Flag{PS04_M_DNS_INTERNAL_MAP}
HOSTS_EOF
chmod 644 "${PS04}/medium/03_dns_mapping/hosts_override"
chown -R "${LAB_USER}:${LAB_USER}" "${PS04}/medium/03_dns_mapping"

# HARD-01
mkdir -p "${PS04}/hard/01_nfs_bypass"
cat > "${PS04}/hard/01_nfs_bypass/exports_leak" << 'NFS_EOF'
/srv/nfs_share  *(rw,sync,no_root_squash,no_subtree_check)
# Flag: Flag{PS04_H_NFS_ROOT_SQUASH_BYPASS}
NFS_EOF
plant_hard_flag "Flag{PS04_H_NFS_ROOT_SQUASH_BYPASS}" "nfs_export" "nfs_mount_key_2024"
chmod 644 "${PS04}/hard/01_nfs_bypass/exports_leak"
chown -R "${LAB_USER}:${LAB_USER}" "${PS04}/hard/01_nfs_bypass"

# HARD-02
mkdir -p "${PS04}/hard/02_ipc_socket_leak"
mkfifo "${PS04}/hard/02_ipc_socket_leak/.ipc_stream" 2>/dev/null || true
echo "Flag{PS04_H_IPC_UNENCRYPTED_SOCKET}" | base64 > "${PS04}/hard/02_ipc_socket_leak/.socket_buffer_log"
cat > "${PS04}/hard/02_ipc_socket_leak/start_ipc_server.sh" << 'IPC_EOF'
#!/bin/bash
SOCKET_PATH="/tmp/.lab_ipc_$(date +%s).sock"
echo "Listening on ${SOCKET_PATH}..."
echo "QTVJRFlUX0ZMQUc6IFBpZ1BpZzA0X0hBX0lQQ19VTkVOQ1JZUFRFRF9TT0NLRVQ=" | base64 -d > /tmp/.flag_output 2>/dev/null
IPC_EOF
chmod +x "${PS04}/hard/02_ipc_socket_leak/start_ipc_server.sh"
chown -R "${LAB_USER}:${LAB_USER}" "${PS04}/hard/02_ipc_socket_leak"
log_ok "PS-04 deployed with 8 challenge states"

# ---- PS-05 ----
log_section "PS-05: Boot Integrity and Systemd Unit Lifecycles"
PS05="${LAB_HOME}/PS-05"
mkdir -p "${PS05}/easy" "${PS05}/medium" "${PS05}/hard"

generate_readme "${PS05}" "05" "Boot Integrity and Systemd Unit Lifecycles" \
"Boot process misconfigurations — readable GRUB configs, writable systemd units, and loose initramfs parameters — allow attackers to establish persistence, disable security controls, or load malicious kernels. Auditing boot integrity is critical for early detection of firmware-level compromises." \
"- systemctl list-units\n- systemctl cat <unit>\n- journalctl -u <unit>\n- grub-mkconfig / grub.cfg inspection\n- lsinitramfs\n- crontab -l\n- lsmod" \
"During a compromise assessment, a threat actor had added a malicious systemd oneshot service that re-established C2 on reboot. Students must audit systemd unit definitions, boot parameters, cron jobs, and initramfs contents for persistence mechanisms."

# EASY-01
mkdir -p "${PS05}/easy/01_grub_leak"
cat > "${PS05}/easy/01_grub_leak/grub_cfg_leak" << 'GRUB_EOF'
set default="0"
set timeout="5"
menuentry 'Kali GNU/Linux' {
    linux /vmlinuz-6.1.0-kali5-amd64 root=/dev/sda1 ro quiet splash
    initrd /initrd.img-6.1.0-kali5-amd64
}
# Flag: Flag{PS05_E_GRUB_READABLE}
GRUB_EOF
chmod 644 "${PS05}/easy/01_grub_leak/grub_cfg_leak"
chown -R "${LAB_USER}:${LAB_USER}" "${PS05}/easy/01_grub_leak"

# EASY-02
mkdir -p "${PS05}/easy/02_init_backup"
cat > "${PS05}/easy/02_init_backup/init_params_backup.conf" << 'INIT_EOF'
kernel_params="mitigations=off intel_iommu=off nopti nospectre_v2"
# Flag: Flag{PS05_E_INIT_PARAM_BACKUP}
INIT_EOF
chmod 644 "${PS05}/easy/02_init_backup/init_params_backup.conf"
chown -R "${LAB_USER}:${LAB_USER}" "${PS05}/easy/02_init_backup"

# EASY-03
mkdir -p "${PS05}/easy/03_rescue_target"
cat > "${PS05}/easy/03_rescue_target/rescue.service_leak" << 'RESCUE_EOF'
[Unit]
Description=Rescue mode with debug shell
DefaultDependencies=no

[Service]
ExecStart=/bin/bash -c 'echo Flag{PS05_E_RESCUE_TARGET_ACTIVE} > /tmp/.rescue_flag'
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=rescue.target
RESCUE_EOF
chmod 644 "${PS05}/easy/03_rescue_target/rescue.service_leak"
chown -R "${LAB_USER}:${LAB_USER}" "${PS05}/easy/03_rescue_target"

# MEDIUM-01
mkdir -p "${PS05}/medium/01_writable_systemd_unit"
cat > "${PS05}/medium/01_writable_systemd_unit/evil.service_leak" << 'UNIT_EOF'
[Unit]
Description=Legitimate-looking service
After=network.target

[Service]
ExecStart=/bin/bash -c 'echo Flag{PS05_M_WRITABLE_SYSTEMD_UNIT} > /tmp/.systemd_flag'
Type=simple
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT_EOF
chmod 666 "${PS05}/medium/01_writable_systemd_unit/evil.service_leak"
chown -R "${LAB_USER}:${LAB_USER}" "${PS05}/medium/01_writable_systemd_unit"

# MEDIUM-02
mkdir -p "${PS05}/medium/02_cron_reboot"
cat > "${PS05}/medium/02_cron_reboot/root_crontab_leak" << 'CRON_EOF'
@reboot root /bin/bash -c 'echo Flag{PS05_M_CRON_REBOOT_PERSISTENCE} > /var/log/.cron_persistence'
@reboot root /usr/local/bin/unknown_script.sh
@daily root /opt/backup.sh
CRON_EOF
chmod 644 "${PS05}/medium/02_cron_reboot/root_crontab_leak"
chown -R "${LAB_USER}:${LAB_USER}" "${PS05}/medium/02_cron_reboot"

# MEDIUM-03
mkdir -p "${PS05}/medium/03_driver_blacklist"
cat > "${PS05}/medium/03_driver_blacklist/blacklist_leak.conf" << 'BLACKLIST_EOF'
blacklist uvcvideo
blacklist btusb
blacklist pcspkr
# Flag: Flag{PS05_M_DRIVER_BLACKLIST_LOOSE}
BLACKLIST_EOF
chmod 644 "${PS05}/medium/03_driver_blacklist/blacklist_leak.conf"
chown -R "${LAB_USER}:${LAB_USER}" "${PS05}/medium/03_driver_blacklist"

# HARD-01
mkdir -p "${PS05}/hard/01_initramfs_alt"
mkdir -p /tmp/extracted_initramfs
echo "Flag{PS05_H_INITRAMFS_ALT_STRUCTURE}" > /tmp/extracted_initramfs/.init_flag
cd "${PS05}/hard/01_initramfs_alt"
tar czf initramfs_sim.img -C /tmp extracted_initramfs/ 2>/dev/null || tar czf initramfs_sim.img -T /dev/null
rm -rf /tmp/extracted_initramfs/
chmod 644 initramfs_sim.img
cd /
chown -R "${LAB_USER}:${LAB_USER}" "${PS05}/hard/01_initramfs_alt"

# HARD-02
mkdir -p "${PS05}/hard/02_early_boot_persistence"
cat > "${PS05}/hard/02_early_boot_persistence/early_boot_hook.sh" << 'EARLY_EOF'
#!/bin/bash
echo "Flag{PS05_H_EARLY_BOOT_PERSISTENCE}" > /etc/.early_boot_marker
EARLY_EOF
chmod +x "${PS05}/hard/02_early_boot_persistence/early_boot_hook.sh"
chown -R "${LAB_USER}:${LAB_USER}" "${PS05}/hard/02_early_boot_persistence"
log_ok "PS-05 deployed with 8 challenge states"

# ---- PS-06 ----
log_section "PS-06: Display Servers, IPC, and GUI Layers"
PS06="${LAB_HOME}/PS-06"
mkdir -p "${PS06}/easy" "${PS06}/medium" "${PS06}/hard"

generate_readme "${PS06}" "06" "Display Servers, Inter-Process Communication, and GUI Layers" \
"X11 and Wayland display server misconfigurations — readable .Xauthority files, open xhost ACLs, and insecure D-Bus policies — allow attackers to capture keystrokes, hijack GUI sessions, and communicate between sandboxed processes. Auditing these layers is vital for multi-user desktop environments." \
"- xauth list\n- xhost\n- ls -la /tmp/.X*\n- dbus-daemon --config-file\n- dbus-send\n- ls -la ~/.Xauthority\n- journalctl _COMM=gnome-session" \
"In a university lab environment, a student discovered they could read another user's Xauthority file and inject keystrokes into their session. Students must audit display server configurations, IPC permissions, and autostart mechanisms."

# EASY-01
mkdir -p "${PS06}/easy/01_xauthority_leak"
touch "${PS06}/easy/01_xauthority_leak/.Xauthority"
echo -e "\x00\x01\x02\x03MAGIC\x04\x05\x06\x07Flag{PS06_E_XAUTHORITY_LEAK}" > "${PS06}/easy/01_xauthority_leak/.Xauthority"
chmod 644 "${PS06}/easy/01_xauthority_leak/.Xauthority"
chown -R "${LAB_USER}:${LAB_USER}" "${PS06}/easy/01_xauthority_leak"

# EASY-02
mkdir -p "${PS06}/easy/02_init_scripts"
cat > "${PS06}/easy/02_init_scripts/xinitrc_leak" << 'XINIT_EOF'
#!/bin/bash
xhost +local:
xsetroot -solid grey
# Flag: Flag{PS06_E_XINITRC_WORLD_READ}
XINIT_EOF
chmod 644 "${PS06}/easy/02_init_scripts/xinitrc_leak"
chown -R "${LAB_USER}:${LAB_USER}" "${PS06}/easy/02_init_scripts"

# EASY-03
mkdir -p "${PS06}/easy/03_auto_graphical"
cat > "${PS06}/easy/03_auto_graphical/gdm3_custom.conf" << 'GDM_EOF'
[security]
AllowRoot=true
DisallowTCP=false

[debug]
Enable=true
# Flag: Flag{PS06_E_GDM_AUTO_SESSION}
GDM_EOF
chmod 644 "${PS06}/easy/03_auto_graphical/gdm3_custom.conf"
chown -R "${LAB_USER}:${LAB_USER}" "${PS06}/easy/03_auto_graphical"

# MEDIUM-01
mkdir -p "${PS06}/medium/01_remote_desktop_leak"
cat > "${PS06}/medium/01_remote_desktop_leak/vnc_config_leak" << 'VNC_EOF'
SecurityTypes=VncAuth
Password=lab123
# Flag: Flag{PS06_M_VNC_PLAINTEXT_CONFIG}
VNC_EOF
chmod 644 "${PS06}/medium/01_remote_desktop_leak/vnc_config_leak"
chown -R "${LAB_USER}:${LAB_USER}" "${PS06}/medium/01_remote_desktop_leak"

# MEDIUM-02
mkdir -p "${PS06}/medium/02_open_display"
cat > "${PS06}/medium/02_open_display/xhost_output.txt" << 'XHOST_EOF'
access control enabled, only authorized clients can connect
SI:localuser:root
SI:localuser:hackathon_lab
# INET:localhost — anyone from localhost can connect
# Flag: Flag{PS06_M_OPEN_XHOST_DISPLAY}
XHOST_EOF
chmod 644 "${PS06}/medium/02_open_display/xhost_output.txt"
chown -R "${LAB_USER}:${LAB_USER}" "${PS06}/medium/02_open_display"

# MEDIUM-03
mkdir -p "${PS06}/medium/03_wm_logs"
cat > "${PS06}/medium/03_wm_logs/wm_notification.log" << 'WM_EOF'
[2024-01-15 10:23:45] Window manager started with debug enabled
[2024-01-15 10:23:46] Registered compositor: mutter
[2024-01-15 10:23:47] AUDIT_FLAG: Flag{PS06_M_WM_NOTIFICATION_LEAK}
[2024-01-15 10:23:48] XKB: keyboard layout changed
WM_EOF
chmod 644 "${PS06}/medium/03_wm_logs/wm_notification.log"
chown -R "${LAB_USER}:${LAB_USER}" "${PS06}/medium/03_wm_logs"

# HARD-01
mkdir -p "${PS06}/hard/01_dbus_policy"
cat > "${PS06}/hard/01_dbus_policy/dbus_allow_all.conf" << 'DBUS_EOF'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow receive_sender="*" eavesdrop="true"/>
    <allow own="*"/>
  </policy>
  <!-- Flag: Flag{PS06_H_DBUS_WEAK_POLICY} -->
</busconfig>
DBUS_EOF
chmod 644 "${PS06}/hard/01_dbus_policy/dbus_allow_all.conf"
chown -R "${LAB_USER}:${LAB_USER}" "${PS06}/hard/01_dbus_policy"

# HARD-02
mkdir -p "${PS06}/hard/02_autostart_background"
mkdir -p "${PS06}/hard/02_autostart_background/.config/autostart"
cat > "${PS06}/hard/02_autostart_background/.config/autostart/cleanup.desktop" << 'AUTOSTART_EOF'
[Desktop Entry]
Type=Application
Name=System Cleanup
Exec=/bin/bash -c 'echo Flag{PS06_H_AUTOSTART_BACKGROUND_TASK} > /tmp/.autostart_flag; sleep 3600'
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name[en_US]=System Cleanup
AUTOSTART_EOF
chmod 644 "${PS06}/hard/02_autostart_background/.config/autostart/cleanup.desktop"
cat > "${PS06}/hard/02_autostart_background/background_worker.sh" << 'WORKER_EOF'
#!/bin/bash
while true; do
    echo "Flag{PS06_H_AUTOSTART_WORKER}" >> /tmp/.worker_audit.log
    sleep 30
done
WORKER_EOF
chmod +x "${PS06}/hard/02_autostart_background/background_worker.sh"
chown -R "${LAB_USER}:${LAB_USER}" "${PS06}/hard/02_autostart_background"
log_ok "PS-06 deployed with 8 challenge states"

# ---- PS-07 ----
log_section "PS-07: Storage Boundaries, Symlinks, and File Systems"
PS07="${LAB_HOME}/PS-07"
mkdir -p "${PS07}/easy" "${PS07}/medium" "${PS07}/hard"

generate_readme "${PS07}" "07" "Storage Boundaries, Symlinks, and File Systems" \
"File system auditing — writable system paths, dangerous symlinks, stale UIDs/GIDs, and unisolated loop devices — is foundational for detecting file-based privilege escalation, data leakage, and integrity violations. Attackers frequently exploit symlinks for TOCTOU attacks and writable paths for binary planting." \
"- find / -type f -perm -o+w\n- stat\n- ls -la\n- readlink\n- findmnt\n- losetup -a\n- mount -l\n- find / -nouser -o -nogroup" \
"A penetration test revealed that a world-writable script in /usr/local/bin was being executed by a cron job (DACL bypass via writable path). Students must audit file permissions, symbolic link chains, orphaned objects, and mount configurations."

# EASY-01
mkdir -p "${PS07}/easy/01_writable_maintenance"
cat > "${PS07}/easy/01_writable_maintenance/daily_maintenance.sh" << 'MAINT_EOF'
#!/bin/bash
echo "Maintenance running..."
# Flag: Flag{PS07_E_WRITABLE_MAINT_SCRIPT}
MAINT_EOF
chmod 666 "${PS07}/easy/01_writable_maintenance/daily_maintenance.sh"
chown -R "${LAB_USER}:${LAB_USER}" "${PS07}/easy/01_writable_maintenance"

# EASY-02
mkdir -p "${PS07}/easy/02_cleartext_tmp"
echo "db_password=Flag{PS07_E_CLEARTEXT_TMP_LEAK}" > "${PS07}/easy/02_cleartext_tmp/app_config.bak"
echo "api_key=sk-1234-flag-audit-token" >> "${PS07}/easy/02_cleartext_tmp/app_config.bak"
echo "secret=Flag{PS07_E_TMP_CREDENTIALS}" >> "${PS07}/easy/02_cleartext_tmp/app_config.bak"
chmod 644 "${PS07}/easy/02_cleartext_tmp/app_config.bak"
chown -R "${LAB_USER}:${LAB_USER}" "${PS07}/easy/02_cleartext_tmp"

# EASY-03
mkdir -p "${PS07}/easy/03_orphaned_fragments"
cat > "${PS07}/easy/03_orphaned_fragments/deleted_user_data.txt" << 'ORPHAN_EOF'
This file belonged to a deleted user (UID 9999)
Contains sensitive residual data
Flag{PS07_E_ORPHANED_STORAGE}
ORPHAN_EOF
chown 9999:9999 "${PS07}/easy/03_orphaned_fragments/deleted_user_data.txt" 2>/dev/null || chown nobody:nogroup "${PS07}/easy/03_orphaned_fragments/deleted_user_data.txt"
chmod 644 "${PS07}/easy/03_orphaned_fragments/deleted_user_data.txt"
chown -R "${LAB_USER}:${LAB_USER}" "${PS07}/easy/03_orphaned_fragments"

# MEDIUM-01
mkdir -p "${PS07}/medium/01_symlink_chain"
ln -sf /etc/shadow "${PS07}/medium/01_symlink_chain/link1" 2>/dev/null || echo "-> /etc/shadow (symlink target)" > "${PS07}/medium/01_symlink_chain/link1"
ln -sf link1 "${PS07}/medium/01_symlink_chain/link2"
ln -sf link2 "${PS07}/medium/01_symlink_chain/link3"
echo "Flag{PS07_M_SYMLINK_CHAIN_DATABASE}" > "${PS07}/medium/01_symlink_chain/.target_file"
plant_easy_flag "${PS07}/medium/01_symlink_chain/.target_file" "Flag{PS07_M_SYMLINK_RESOLUTION}"
chown -R "${LAB_USER}:${LAB_USER}" "${PS07}/medium/01_symlink_chain"

# MEDIUM-02
mkdir -p "${PS07}/medium/02_sticky_bit_abuse"
mkdir -p "${PS07}/medium/02_sticky_bit_abuse/shared_tmp"
chmod 777 "${PS07}/medium/02_sticky_bit_abuse/shared_tmp"
mkdir -p "${PS07}/medium/02_sticky_bit_abuse/proper_tmp"
chmod 1777 "${PS07}/medium/02_sticky_bit_abuse/proper_tmp"
echo "Flag{PS07_M_STICKY_BIT_OVERRIDE}" > "${PS07}/medium/02_sticky_bit_abuse/shared_tmp/.flag"
chmod 644 "${PS07}/medium/02_sticky_bit_abuse/shared_tmp/.flag"
chown -R "${LAB_USER}:${LAB_USER}" "${PS07}/medium/02_sticky_bit_abuse"

# MEDIUM-03
mkdir -p "${PS07}/medium/03_stale_profiles"
cat > "${PS07}/medium/03_stale_profiles/deleted_user_bashrc" << 'STALE_EOF'
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HISTFILE="/dev/null"
alias sudo='sudo '
# Flag: Flag{PS07_M_STALE_PROFILE_ARTIFACT}
STALE_EOF
chmod 644 "${PS07}/medium/03_stale_profiles/deleted_user_bashrc"
chown -R "${LAB_USER}:${LAB_USER}" "${PS07}/medium/03_stale_profiles"

# HARD-01
mkdir -p "${PS07}/hard/01_nonexistent_uid"
touch "${PS07}/hard/01_nonexistent_uid/residual_data.bin"
chown 59999:59999 "${PS07}/hard/01_nonexistent_uid/residual_data.bin" 2>/dev/null || true
echo "Flag{PS07_H_NONEXISTENT_UID}" > "${PS07}/hard/01_nonexistent_uid/residual_data.bin"
chmod 644 "${PS07}/hard/01_nonexistent_uid/residual_data.bin"
chown -R "${LAB_USER}:${LAB_USER}" "${PS07}/hard/01_nonexistent_uid" 2>/dev/null || true

# HARD-02
mkdir -p "${PS07}/hard/02_loop_no_isolation"
dd if=/dev/zero of="${PS07}/hard/02_loop_no_isolation/disk_img.img" bs=1M count=10 2>/dev/null
mkfs.ext4 -F "${PS07}/hard/02_loop_no_isolation/disk_img.img" 2>/dev/null || true
echo "Flag{PS07_H_LOOP_NO_ISOLATION}" > "${PS07}/hard/02_loop_no_isolation/mount_options.txt"
cat > "${PS07}/hard/02_loop_no_isolation/mount_leak" << 'MOUNT_EOF'
/dev/loop0 on /mnt/unsafe type ext4 (rw,suid,dev,exec,relatime)
# MISSING: nodev,nosuid,noexec
# Flag{PS07_H_LOOP_MOUNT_LEAK}
MOUNT_EOF
chmod 644 "${PS07}/hard/02_loop_no_isolation/mount_leak"
chown -R "${LAB_USER}:${LAB_USER}" "${PS07}/hard/02_loop_no_isolation"
log_ok "PS-07 deployed with 8 challenge states"

# ---- PS-08 ----
log_section "PS-08: Log Rotation, Auditing Engines, and Monitoring"
PS08="${LAB_HOME}/PS-08"
mkdir -p "${PS08}/easy" "${PS08}/medium" "${PS08}/hard"

generate_readme "${PS08}" "08" "Log Rotation, Auditing Engines, and Monitoring" \
"Logging and auditing misconfigurations allow attackers to cover their tracks, disable accountability, and exfiltrate data without detection. Modified rsyslog routing, suppressed auditd rules, and unrotated logs are common evasion targets. Auditing the logging pipeline is essential for forensic readiness." \
"- rsyslogd / journalctl\n- auditctl / auditd\n- ausearch / aureport\n- logrotate -d\n- ls -la /var/log/\n- strings /var/log/*\n- systemd-journald" \
"During a DFIR engagement, analysts discovered that rsyslog had been reconfigured to drop authpriv messages. Students must audit log routing, journal visibility, auditd suppression, and log buffer configurations."

# EASY-01
mkdir -p "${PS08}/easy/01_rsyslog_drop"
cat > "${PS08}/easy/01_rsyslog_drop/rsyslog_drop_security.conf" << 'RSYSLOG_EOF'
auth,authpriv.none  /var/log/auth.log
*.info;mail.none;authpriv.none;cron.none  /var/log/messages
# SECURITY FACILITY DROPPED: Flag{PS08_E_RSYSLOG_DROP}
RSYSLOG_EOF
chmod 644 "${PS08}/easy/01_rsyslog_drop/rsyslog_drop_security.conf"
chown -R "${LAB_USER}:${LAB_USER}" "${PS08}/easy/01_rsyslog_drop"

# EASY-02
mkdir -p "${PS08}/easy/02_unrotated_logs"
dd if=/dev/zero of="${PS08}/easy/02_unrotated_logs/access.log" bs=1M count=10 2>/dev/null
echo "AUDIT_FLAG: Flag{PS08_E_UNROTATED_HUGE_LOG}" | dd of="${PS08}/easy/02_unrotated_logs/access.log" bs=1 seek=42 conv=notrunc 2>/dev/null
chmod 644 "${PS08}/easy/02_unrotated_logs/access.log"
chown -R "${LAB_USER}:${LAB_USER}" "${PS08}/easy/02_unrotated_logs"

# EASY-03
mkdir -p "${PS08}/easy/03_truncated_traces"
cat > "${PS08}/easy/03_truncated_traces/exec_trace.log" << 'TRACE_EOF'
EXEC: /usr/bin/sshd [PID: 1234]
EXEC: /bin/bash [PID: 1235]
EXEC: /usr/bin/wget [PID: 1236]
... (trace truncated at 10 entries)
# TRUNCATED: Flag{PS08_E_TRUNCATED_EXEC_TRACE}
TRACE_EOF
chmod 644 "${PS08}/easy/03_truncated_traces/exec_trace.log"
chown -R "${LAB_USER}:${LAB_USER}" "${PS08}/easy/03_truncated_traces"

# MEDIUM-01
mkdir -p "${PS08}/medium/01_log_exposure"
cat > "${PS08}/medium/01_log_exposure/application_2024.log" << 'APP_LOG_EOF'
[2024-01-15 10:23:45] INFO  Starting application server
[2024-01-15 10:23:46] DEBUG Connecting to database: postgresql://admin:P@ssw0rd!@db.internal:5432/prod
[2024-01-15 10:23:47] DEBUG AWS Secret: AKIA1234567890ABCDEF
[2024-01-15 10:23:48] AUDIT_FLAG: Flag{PS08_M_LOG_CONNECTION_LEAK}
[2024-01-15 10:23:49] INFO  Server started on port 8080
APP_LOG_EOF
chmod 644 "${PS08}/medium/01_log_exposure/application_2024.log"
chown -R "${LAB_USER}:${LAB_USER}" "${PS08}/medium/01_log_exposure"

# MEDIUM-02
mkdir -p "${PS08}/medium/02_journal_visibility"
cat > "${PS08}/medium/02_journal_visibility/journald_leak.conf" << 'JOURNAL_EOF'
Storage=persistent
Compress=yes
ForwardToSyslog=yes
MaxRetentionSec=0
# No ACL restrictions — all users can read
# Flag: Flag{PS08_M_JOURNAL_VISIBILITY_LEAK}
JOURNAL_EOF
chmod 644 "${PS08}/medium/02_journal_visibility/journald_leak.conf"
chown -R "${LAB_USER}:${LAB_USER}" "${PS08}/medium/02_journal_visibility"

# MEDIUM-03
mkdir -p "${PS08}/medium/03_auditd_suppression"
cat > "${PS08}/medium/03_auditd_suppression/auditd_suppress.rules" << 'AUDIT_EOF'
-a exclude,always -F msgtype=USER_LOGIN
-a exclude,always -F msgtype=USER_END
-a exclude,always -F msgtype=CRED_ACQ
# SUPPRESSED: Flag{PS08_M_AUDITD_SUPPRESS}
AUDIT_EOF
chmod 644 "${PS08}/medium/03_auditd_suppression/auditd_suppress.rules"
chown -R "${LAB_USER}:${LAB_USER}" "${PS08}/medium/03_auditd_suppression"

# HARD-01
mkdir -p "${PS08}/hard/01_log_buffer_mask"
cat > "${PS08}/hard/01_log_buffer_mask/rsyslog_buffer_leak.conf" << 'BUFFER_EOF'
$ActionQueueMaxDiskSpace 1g
$ActionQueueSaveOnShutdown off
$ActionQueueType LinkedList
$ActionResumeRetryCount 0
# Queue overflow causes message drops — operational state masked
# Flag: Flag{PS08_H_LOG_BUFFER_MASK}
BUFFER_EOF
chmod 644 "${PS08}/hard/01_log_buffer_mask/rsyslog_buffer_leak.conf"
chown -R "${LAB_USER}:${LAB_USER}" "${PS08}/hard/01_log_buffer_mask"

# HARD-02
mkdir -p "${PS08}/hard/02_disabled_event_profiles"
cat > "${PS08}/hard/02_disabled_event_profiles/audit_profile_disabled.sh" << 'PROFILE_EOF'
#!/bin/bash
echo "Running scheduled system maintenance..."
# Hidden: disable audit profile for cleanup
# Flag{PS08_H_DISABLED_AUDIT_PROFILE}
echo "Maintenance complete."
PROFILE_EOF
chmod +x "${PS08}/hard/02_disabled_event_profiles/audit_profile_disabled.sh"
chown -R "${LAB_USER}:${LAB_USER}" "${PS08}/hard/02_disabled_event_profiles"
log_ok "PS-08 deployed with 8 challenge states"

# ---- PS-09 ----
log_section "PS-09: Cryptographic Protocols, Key Material, and Secrets Management"
PS09="${LAB_HOME}/PS-09"
mkdir -p "${PS09}/easy" "${PS09}/medium" "${PS09}/hard"

generate_readme "${PS09}" "09" "Cryptographic Protocols, Key Material, and Secrets Management" \
"Cryptographic protocol implementation flaws, key exposures, and hardcoded credentials represent massive risks to enterprise integrity. Auditing TLS options, private key permissions, and secrets files prevents severe compromise." \
"- openssl\n- ssh-keygen\n- grep\n- find\n- ssh\n- systemd-analyze" \
"An external audit of a backup server identified exposed private keys and weak cipher configurations. Students must locate cryptographic vulnerabilities, inspect certificate properties, and extract hidden configuration flags."

# EASY-01
mkdir -p "${PS09}/easy/01_exposed_keys"
cat > "${PS09}/easy/01_exposed_keys/id_rsa_backup" << 'KEY_EOF'
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0y1g...
# Flag{PS09_E_EXPOSED_PRIVATE_KEY}
-----END RSA PRIVATE KEY-----
KEY_EOF
chmod 644 "${PS09}/easy/01_exposed_keys/id_rsa_backup"
chown -R "${LAB_USER}:${LAB_USER}" "${PS09}/easy/01_exposed_keys"

# EASY-02
mkdir -p "${PS09}/easy/02_weak_ciphers"
cat > "${PS09}/easy/02_weak_ciphers/openssl_audit.cnf" << 'CIPHER_EOF'
[system_default_sect]
CipherString = DEFAULT@SECLEVEL=1
# Flag: Flag{PS09_E_WEAK_CIPHER_SUITES}
CIPHER_EOF
chmod 644 "${PS09}/easy/02_weak_ciphers/openssl_audit.cnf"
chown -R "${LAB_USER}:${LAB_USER}" "${PS09}/easy/02_weak_ciphers"

# EASY-03
mkdir -p "${PS09}/easy/03_hardcoded_secrets"
cat > "${PS09}/easy/03_hardcoded_secrets/db_backup.sh" << 'SECRET_EOF'
#!/bin/bash
DB_USER="backup_agent"
DB_PASS="Flag{PS09_E_HARDCODED_SECRETS}"
pg_dump -U "$DB_USER" -h localhost production_db > /tmp/backup.sql
SECRET_EOF
chmod 755 "${PS09}/easy/03_hardcoded_secrets/db_backup.sh"
chown -R "${LAB_USER}:${LAB_USER}" "${PS09}/easy/03_hardcoded_secrets"

# MEDIUM-01
mkdir -p "${PS09}/medium/01_weak_cert"
cat > "${PS09}/medium/01_weak_cert/weak_cert.pem" << 'CERT_EOF'
-----BEGIN CERTIFICATE-----
MIIDBjCCAe4gAwIBAgIUFlag{PS09_M_WEAK_CERTIFICATE}
-----END CERTIFICATE-----
CERT_EOF
plant_medium_flag "Flag{PS09_M_WEAK_CERTIFICATE}" "weak_cert"
chmod 644 "${PS09}/medium/01_weak_cert/weak_cert.pem"
chown -R "${LAB_USER}:${LAB_USER}" "${PS09}/medium/01_weak_cert"

# MEDIUM-02
mkdir -p "${PS09}/medium/02_ssh_client_config"
cat > "${PS09}/medium/02_ssh_client_config/ssh_config_audit" << 'SSH_CLIENT_EOF'
Host *
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    # Flag: Flag{PS09_M_PERMISSIVE_SSH_CLIENT}
SSH_CLIENT_EOF
plant_medium_flag "Flag{PS09_M_PERMISSIVE_SSH_CLIENT}" "ssh_client"
chmod 644 "${PS09}/medium/02_ssh_client_config/ssh_config_audit"
chown -R "${LAB_USER}:${LAB_USER}" "${PS09}/medium/02_ssh_client_config"

# MEDIUM-03
mkdir -p "${PS09}/medium/03_systemd_env"
cat > "${PS09}/medium/03_systemd_env/app_secrets.env" << 'ENV_EOF'
SECRET_KEY=Flag{PS09_M_SYSTEMD_ENV_SECRETS}
API_ENDPOINT=https://api.internal/v1
ENV_EOF
plant_medium_flag "Flag{PS09_M_SYSTEMD_ENV_SECRETS}" "systemd_env"
chmod 600 "${PS09}/medium/03_systemd_env/app_secrets.env"
chown -R "${LAB_USER}:${LAB_USER}" "${PS09}/medium/03_systemd_env"

# HARD-01
mkdir -p "${PS09}/hard/01_encrypted_backup"
cat > "${PS09}/hard/01_encrypted_backup/decrypt_backup.sh" << 'DECRYPT_EOF'
#!/bin/bash
# Backup is encrypted with password 'crypto_audit_2024'
# Flag is inside the encrypted file. Use plant_hard_flag key to retrieve.
DECRYPT_EOF
plant_hard_flag "Flag{PS09_H_ENCRYPTED_BACKUP_KEY}" "crypto_backup" "crypto_audit_2024"
chmod 755 "${PS09}/hard/01_encrypted_backup/decrypt_backup.sh"
chown -R "${LAB_USER}:${LAB_USER}" "${PS09}/hard/01_encrypted_backup"

# HARD-02
mkdir -p "${PS09}/hard/02_nginx_tls"
cat > "${PS09}/hard/02_nginx_tls/nginx_ssl.conf" << 'NGINX_EOF'
server {
    listen 443 ssl;
    ssl_protocols SSLv3 TLSv1 TLSv1.1;
    ssl_ciphers RC4-SHA:RC4-MD5;
    # Flag: Flag{PS09_H_TLS_FALLBACK_VULN}
}
NGINX_EOF
chmod 644 "${PS09}/hard/02_nginx_tls/nginx_ssl.conf"
chown -R "${LAB_USER}:${LAB_USER}" "${PS09}/hard/02_nginx_tls"
log_ok "PS-09 deployed with 8 challenge states"

# ---- PS-10 ----
log_section "PS-10: Virtualization, Container Boundaries, and Namespace Isolation"
PS10="${LAB_HOME}/PS-10"
mkdir -p "${PS10}/easy" "${PS10}/medium" "${PS10}/hard"

generate_readme "${PS10}" "10" "Virtualization, Container Boundaries, and Namespace Isolation" \
"Containerization is ubiquitous, but weak namespace isolation and over-privileged runtimes allow attackers to break container boundaries. Auditing container configuration templates and isolation levels prevents sandbox escapes." \
"- docker\n- cgroups\n- ip netns\n- apparmor_status\n- capsh\n- jq" \
"A microservice host was compromised because a developer mounted the docker socket into a staging container. Students must audit configuration files, identify privilege boundaries, and extract keys from simulated sandbox escapes."

# EASY-01
mkdir -p "${PS10}/easy/01_docker_socket"
touch "${PS10}/easy/01_docker_socket/docker.sock"
chmod 777 "${PS10}/easy/01_docker_socket/docker.sock"
plant_easy_flag "${PS10}/easy/01_docker_socket/docker.sock" "Flag{PS10_E_EXPOSED_DOCKER_SOCKET}"
chown -R "${LAB_USER}:${LAB_USER}" "${PS10}/easy/01_docker_socket"

# EASY-02
mkdir -p "${PS10}/easy/02_privileged_container"
cat > "${PS10}/easy/02_privileged_container/docker-compose.yml" << 'COMPOSE_EOF'
version: '3.8'
services:
  webapp:
    image: webapp:latest
    privileged: true
    # Flag{PS10_E_PRIVILEGED_CONTAINER}
COMPOSE_EOF
chmod 644 "${PS10}/easy/02_privileged_container/docker-compose.yml"
chown -R "${LAB_USER}:${LAB_USER}" "${PS10}/easy/02_privileged_container"

# EASY-03
mkdir -p "${PS10}/easy/03_apparmor_profile"
cat > "${PS10}/easy/03_apparmor_profile/profile_weak" << 'APPARMOR_EOF'
profile weak-profile flags=(attach_disconnected) {
    file,
    # Flag{PS10_E_WEAK_APPARMOR_PROFILE}
}
APPARMOR_EOF
chmod 644 "${PS10}/easy/03_apparmor_profile/profile_weak"
chown -R "${LAB_USER}:${LAB_USER}" "${PS10}/easy/03_apparmor_profile"

# MEDIUM-01
mkdir -p "${PS10}/medium/01_shared_namespaces"
cat > "${PS10}/medium/01_shared_namespaces/pod_spec.yaml" << 'POD_EOF'
apiVersion: v1
kind: Pod
metadata:
  name: admin-helper
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: helper
    image: alpine:latest
    # Flag: Flag{PS10_M_SHARED_NAMESPACES}
POD_EOF
plant_medium_flag "Flag{PS10_M_SHARED_NAMESPACES}" "pod_spec"
chmod 644 "${PS10}/medium/01_shared_namespaces/pod_spec.yaml"
chown -R "${LAB_USER}:${LAB_USER}" "${PS10}/medium/01_shared_namespaces"

# MEDIUM-02
mkdir -p "${PS10}/medium/02_cgroups_config"
cat > "${PS10}/medium/02_cgroups_config/unlimited.slice" << 'CGROUP_EOF'
[Slice]
CPUAccounting=false
MemoryAccounting=false
# Flag: Flag{PS10_M_CGROUP_LIMITS}
CGROUP_EOF
plant_medium_flag "Flag{PS10_M_CGROUP_LIMITS}" "cgroup_slice"
chmod 644 "${PS10}/medium/02_cgroups_config/unlimited.slice"
chown -R "${LAB_USER}:${LAB_USER}" "${PS10}/medium/02_cgroups_config"

# MEDIUM-03
mkdir -p "${PS10}/medium/03_k8s_token"
cat > "${PS10}/medium/03_k8s_token/token" << 'TOKEN_EOF'
eyJhbGciOiJSUzI1NiIsImt...
Flag{PS10_M_K8S_TOKEN_EXPOSURE}
TOKEN_EOF
plant_medium_flag "Flag{PS10_M_K8S_TOKEN_EXPOSURE}" "k8s_token"
chmod 644 "${PS10}/medium/03_k8s_token/token"
chown -R "${LAB_USER}:${LAB_USER}" "${PS10}/medium/03_k8s_token"

# HARD-01
mkdir -p "${PS10}/hard/01_containerd_grpc"
cat > "${PS10}/hard/01_containerd_grpc/containerd_config.toml" << 'CONTAINERD_EOF'
[grpc]
  address = "tcp://0.0.0.0:2375"
  # Flag: Flag{PS10_H_CONTAINERD_GRPC_EXPOSED}
CONTAINERD_EOF
plant_hard_flag "Flag{PS10_H_CONTAINERD_GRPC_EXPOSED}" "containerd_grpc" "container_sandbox_2024"
chmod 644 "${PS10}/hard/01_containerd_grpc/containerd_config.toml"
chown -R "${LAB_USER}:${LAB_USER}" "${PS10}/hard/01_containerd_grpc"

# HARD-02
mkdir -p "${PS10}/hard/02_userns_mapping"
cat > "${PS10}/hard/02_userns_mapping/uid_map" << 'MAP_EOF'
0 0 4294967295
# Flag: Flag{PS10_H_USER_NS_ESCALATION}
MAP_EOF
plant_hard_flag "Flag{PS10_H_USER_NS_ESCALATION}" "userns_escalation" "namespace_escape_2024"
chmod 644 "${PS10}/hard/02_userns_mapping/uid_map"
chown -R "${LAB_USER}:${LAB_USER}" "${PS10}/hard/02_userns_mapping"
log_ok "PS-10 deployed with 8 challenge states"

#===============================================================================
# POST-PROVISIONING SETUPS & PERMISSIONS
#===============================================================================

log_section "PHASE 2: Finalizing Permissions and Cleanup"

# Set ownership and permissions on everything in lab user home directory
chown -R "${LAB_USER}:${LAB_USER}" "${LAB_HOME}"
# Ensure hidden flags directory /var/log/.audit_flags is owned by root and readable by none but root
chown -R root:root /var/log/.audit_flags
chmod 700 /var/log/.audit_flags

echo -e "\n${GREEN}${BOLD}[SUCCESS] Hardened OS Audit Lab deployed successfully!${NC}"
echo -e "${INFO} Training environment provisioned for user: ${BOLD}${LAB_USER}${NC}"
echo -e "${INFO} Lab data directory: ${BOLD}${LAB_HOME}${NC}"
