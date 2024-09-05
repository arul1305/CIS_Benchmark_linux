
#!/usr/bin/env bash
#
# CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 custom script
# This is the Script For the CIS ubuntu L1-server profile
# Name                          Date        Description
# ------------------------------------------------------------------------------------------------
# Arulpandiyan Durai        20-09-2023   "CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0"

# Ensure script is executed in bash

## 1 - Initial Setup
#1
#1.9    Ensure updates, patches, and additional security software are installed
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt upgrade -y
apt install unzip -y
#1.1.9  Disable Automounting
systemctl disable autofs
#1.1.10 Disable USB Storage
echo "install usb-storage /bin/true" >>  /etc/modprobe.d/usb_storage.conf
echo "blacklist usb-storage" >>  /etc/modprobe.d/blacklist.conf
rmmod usb-storage
#1.1.1  Disable unused filesystems
#       Disable unused filesystems
#1.1.1.1        Ensure mounting of cramfs filesystems is disabled
echo "install cramfs /bin/true" >>  /etc/modprobe.d/cramfs.conf
echo "blacklist cramfs" >>  /etc/modprobe.d/cramfs.conf
#1.1.2          Configure /tmp, 1.1.2.2 Ensure nodev option set on /tmp partition,1.1.2.3       Ensure noexec option set on /tmp partition,1.1.2.4      Ensure nosuid option set on /tmp partition
systemctl unmask tmp.mount
#1.1.8          Configure /dev/shm,1.1.8.1      Ensure nodev option set on /dev/shm partition,1.1.8.2   Ensure noexec option set on /dev/shm partition,1.1.8.3  Ensure nosuid option set on /dev/shm partition
echo "tmpfs /dev/shm    tmpfs   rw,nosuid,nodev,noexec,inode64  0   1" >>  /etc/fstab
#1.2            Configure Software Updates
#1.2.1  Ensure package manager repositories are configured
#1.2.2  Ensure GPG keys are configured
apt update -y
#1.3            Filesystem Integrity Checking
#1.3.1  Ensure AIDE is installed
export DEBIAN_FRONTEND=noninteractive
apt install aide -y
#1.3.2  Ensure filesystem integrity is regularly checked
crontab -l | { cat; echo "0 5 * * * /usr/sbin/aide --check"; } | crontab -
#1.4            Secure Boot Settings
#1.4.1  Ensure bootloader password is set
echo "Not Applicable in our environment"
#1.4.2  Ensure permissions on bootloader config are configured
chown root:root /boot/grub/grub.cfg
chmod u-wx,go-rwx /boot/grub/grub.cfg
#1.4.3  Ensure authentication required for single user mode
sudo sh -c 'echo root:P@ssw0rd@123 | chpasswd'
#1.5            Additional Process Hardening
#1.5.1  Ensure address space layout randomization (ASLR) is enabled
touch /etc/sysctl.d/cis_sysctl.conf
chmod 0644 /etc/sysctl.d/cis_sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/cis_sysctl.conf
#1.5.2  Ensure prelink is not installed
apt purge prelink -y
apt remove prelink -y
#1.5.3  Ensure Automatic Error Reporting is not enabled
systemctl stop apport.service
systemctl --now disable apport.service
apt purge apport -y
apt remove apport -y
#1.5.4  Ensure core dumps are restricted
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0
systemctl daemon-reload
#1.6            Mandatory Access Control
#1.6.1          Configure AppArmor
#1.6.1  1.6.1.1 Ensure AppArmor is installed
apt install apparmor -y
apt install apparmor-utils -y
#1.6.1.2        Ensure AppArmor is enabled in the bootloader configuration
sed -i '11 a GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"' /etc/default/grub
update-grub
#1.6.1.3        Ensure all AppArmor Profiles are in enforce or complain mode
aa-enforce /etc/apparmor.d/*
#1.7            Command Line Warning Banners
#1.7.1  Ensure message of the day is configured properly
rm -rf /etc/motd
#1.7.2  Ensure local login warning banner is configured properly
echo 'This system is the property of Lean Business services. By using this system, you are responsible for all activities performed using your account. You may only access and use the information on this server for authorized purposes. Any unauthorized access or use of this server may result in disciplinary action. You must comply with all applicable laws and regulations, including those related to Cybersecurity Policies.This server is  monitored for security purposes.' > /etc/issue
#1.7.3  Ensure remote login warning banner is configured properly
echo 'This system is the property of Lean Business services. By using this system, you are responsible for all activities performed using your account. You may only access and use the information on this server for authorized purposes. Any unauthorized access or use of this server may result in disciplinary action. You must comply with all applicable laws and regulations, including those related to Cybersecurity Policies.This server is  monitored for security purposes.' > /etc/issue.net
#1.7.4  Ensure permissions on /etc/motd are configured
chown root:root $(readlink -e /etc/motd)
chmod u-x,go-wx $(readlink -e /etc/motd)
rm -rf /etc/motd
#1.7.5  Ensure permissions on /etc/issue are configured
chown root:root $(readlink -e /etc/issue)
chmod u-x,go-wx $(readlink -e /etc/issue)
#1.7.6  Ensure permissions on /etc/issue.net are configured
chown root:root $(readlink -e /etc/issue.net)
chmod u-x,go-wx $(readlink -e /etc/issue.net)
#1.8            GNOME Display Manager
#1.8.2  Ensure GDM login banner is configured,1.8.3     Ensure GDM disable-user-list option is enabled,1.8.4    Ensure GDM screen locks when the user is idle,1.8.5     Ensure GDM screen locks cannot be overridden,1.8.6  Ensure GDM automatic mounting of removable media is disabled,1.8.7      Ensure GDM disabling automatic mounting of removable media is not overridden,1.8.8      Ensure GDM autorun-never is enabled,1.8.9   Ensure GDM autorun-never is not overridden,1.8.10       Ensure XDCMP is not enabled
apt purge gdm3 -y
apt remove gdm3 -y
#2              Services
#2.4    Ensure nonessential services are removed or masked
#apt remove nftables -y
#2.1            Configure Time Synchronization
#2.1.1          Ensure time synchronization is in use
#2.1.1.1        Ensure a single time synchronization daemon is in use
apt install chrony -y
systemctl stop systemd-timesyncd.service
systemctl --now mask systemd-timesyncd.service
apt purge ntp -y
#2.1.2          Configure chrony
#2.1.2.1        Ensure chrony is configured with authorized timeserver
timedatectl set-timezone Asia/Riyadh
#2.1.2.2        Ensure chrony is running as user _chrony
echo "user _chrony" >> /etc/chrony/chrony.conf
#2.1.2.3        Ensure chrony is enabled and running
systemctl unmask chrony.service
systemctl --now enable chrony.service
#2.1.3          Configure systemd-timesyncd
#2.1.3.1        Ensure systemd-timesyncd configured with authorized timeserver
systemctl --now mask systemd-timesyncd
#2.1.3.2        Ensure systemd-timesyncd is enabled and running
systemctl --now mask systemd-timesyncd.service
#2.1.4          Configure ntp
#2.1.4.1        Ensure ntp access control is configured,2.1.4.2 Ensure ntp is configured with authorized timeserver,2.1.4.3     Ensure ntp is running as user ntp,2.1.4.4       Ensure ntp is enabled and running
apt purge ntp -y
apt remove ntp -y
#2.2            Special Purpose Services
#2.2.1  Ensure X Window System is not installed
apt purge xserver-xorg* -y
#2.2.2  Ensure Avahi Server is not installed
systemctl stop avahi-daaemon.service
systemctl stop avahi-daemon.socket
apt purge avahi-daemon -y
#2.2.3  Ensure CUPS is not installed
apt purge cups -y
#2.2.4  Ensure DHCP Server is not installed
apt purge isc-dhcp-server -y
#2.2.5  Ensure LDAP server is not installed
apt purge slapd -y
#2.2.6  Ensure NFS is not installed
apt purge nfs-kernel-server -y
#2.2.7  Ensure DNS Server is not installed
apt purge bind9 -y
#2.2.8  Ensure FTP Server is not installed
apt purge vsftpd -y
#2.2.9  Ensure HTTP server is not installed
apt purge apache2 -y
#2.2.10 Ensure IMAP and POP3 server are not installed
apt purge dovecot-imapd dovecot-pop3d -y
#2.2.11 Ensure Samba is not installed
apt purge samba -y
#2.2.12 Ensure HTTP Proxy Server is not installed
apt purge squid -y
#2.2.13 Ensure SNMP Server is not installed
apt purge snmp -y
#2.2.14 Ensure NIS Server is not installed
apt purge nis -y
#2.2.15 Ensure mail transfer agent is configured for local-only mode
echo "inet_interfaces = loopback-only" >> /etc/postfix/main.cf
#2.2.16 Ensure rsync service is either not installed or masked
apt purge rsync -y
#2.3            Service Clients
#2.3.1  Ensure NIS Client is not installed
apt purge nis -y
#2.3.2  Ensure rsh client is not installed
apt purge rsh-client -y
#2.3.3  Ensure talk client is not installed
apt purge talk -y
#2.3.4  Ensure telnet client is not installed
apt purge telnet -y
#2.3.5  Ensure LDAP client is not installed
apt purge ldap-utils -y
#2.3.6  Ensure  RPC is not installed
apt purge rpcbind -y
#3              Network Configuration
#3.1    Disable unused network protocols and devices
#3.1.1  Ensure  system is checked to determine if IPv6 is enabled
sed -i '11 a GRUB_CMDLINE_LINUX="ipv6.disable=1"' /etc/default/grub
update-grub
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.d/60-disable_ipv6.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.d/60-disable_ipv6.conf
#3.1.2  Ensure wireless interfaces are disabled
apt pruge wireless-tools -y
#3.2            Network Parameters (Host Only)
#3.2.1  Ensure packet redirect sending is disabled
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
#3.2.2  Ensure IP forwarding is disabled
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
sysctl -w net.ipv4.ip_forward = 0
sysctl -w net.ipv6.conf.all.forwarding = 0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
#3.3            Network Parameters (Host and Router)
#3.3.1  Ensure source routed packets are not accepted
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
#3.3.2  Ensure ICMP redirects are not accepted
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1
#3.3.3  Ensure secure ICMP redirects are not accepted
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
#3.3.4  Ensure suspicious packets are logged
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/60-netipv6_sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/60-netipv6_sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
#3.3.5  Ensure broadcast ICMP requests are ignored
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
#3.3.6  Ensure bogus ICMP responses are ignored
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1
#3.3.7  Ensure Reverse Path Filtering is enabled
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/60-netipv6_sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/60-netipv6_sysctl.conf
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
#3.3.8  Ensure TCP SYN Cookies is enabled
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
#3.3.9  Ensure IPv6 router advertisements are not accepted
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
#3.4            Uncommon Network Protocols
#3.5            Firewall Configuration
#3.5.1          Configure UncomplicatedFirewall
#3.5.1.1        Ensure ufw is installed
apt install ufw -y
yes | ufw enable
#3.5.1.2        Ensure iptables-persistent is not installed with ufw
apt purge iptables-persistent -y
#3.5.1.3        Ensure ufw service is enabled
yes | ufw enable
#3.5.1.4        Ensure ufw loopback traffic is configured
ufw allow in on lo
ufw allow out on lo
ufw deny in from 127.0.0.0/8
ufw deny in from ::1
#3.5.1.5        Ensure ufw outbound connections are configured
ufw allow out on all
#3.5.1.6        Ensure ufw firewall rules exist for all open ports
yes | ufw allow in on lo
ufw allow out on lo
ufw deny in from 127.0.0.0/8
ufw deny in from ::1
ufw allow in 25/tcp
ufw allow in 25/udp
ufw allow in 23/tcp
ufw allow in 23/udp
ufw allow in 22/tcp
ufw allow in 22/udp
ufw logging on
yes | ufw enable
#3.5.1.7        Ensure ufw default deny firewall policy
#ufw default deny incoming
#ufw default deny outgoing
ufw default deny routed
#3.5.3          Configure iptables
#3.5.3.1                Configure iptables software
#3.5.3.1        3.5.3.1.1       Ensure iptables packages are installed
apt install iptables -y
apt install iptables-services -y
#3.5.3.1        3.5.3.1.2       Ensure nftables is not installed with iptables
#apt purge nftables -y
#3.5.3.1        3.5.3.1.3       Ensure ufw is uninstalled or disabled with iptables
#apt purge ufw -y
#yes | ufw disable
#3.5.3.2                Configure IPv4 iptables
#3.5.3.2        3.5.3.2.1       Ensure iptables default deny firewall policy
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
#3.5.3.2        3.5.3.2.2       Ensure iptables loopback traffic is configured
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
#3.5.3.2        3.5.3.2.3       Ensure iptables outbound and established connections are configured
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
service iptables save
#3.5.3.2        3.5.3.2.4       Ensure iptables firewall rules exist for all open ports
sudo iptables -A INPUT -p udp --dport 161 -j ACCEPT
iptables -I INPUT -p udp -m udp --dport 161 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -I INPUT -p udp -m tcp --dport 22 -j ACCEPT
#3.5.3.3                Configure IPv6  ip6tables
#3.5.3.3        3.5.3.3.1       Ensure ip6tables default deny firewall policy
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
#3.5.3.3        3.5.3.3.2       Ensure ip6tables loopback traffic is configured
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -s ::1 -j DROP
#3.5.3.3        3.5.3.3.3       Ensure ip6tables outbound and established connections are configured
ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
service iptables save
#3.5.3.3        3.5.3.3.4       Ensure ip6tables firewall rules exist for all open ports
ip6tables -A INPUT -p udp --dport 161 -j ACCEPT
ip6tables -I INPUT -p udp -m udp --dport 161 -j ACCEPT
#4              Logging and Auditing
#4.1            Configure System Accounting (auditd)
#4.1.1          Ensure auditing is enabled
#4.1.2          Configure Data Retention
#4.1.3          Configure auditd rules
#4.1.4          Configure auditd file access
#4.1.4  4.1.4.1 Ensure audit log files are mode 0640 or less permissive
apt install auditd -y
grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %a:%n
chmod 0600 /var/log/audit/audit.log
chown root:root /var/log/audit/audit.log
#4.1.4  4.1.4.2 Ensure only authorized users own audit log files
[ -f /etc/audit/auditd.conf ] && find '$ (dirname $ (awk -F '=' '/^s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))' -type f ! -user root -exec chown root {} +
#4.1.4  4.1.4.3 Ensure only authorized groups are assigned ownership of audit log files
sudo grep -iw ^log_file /etc/audit/auditd.conf
sudo chown :root /var/log/audit/
echo "log_group = adm" >> /etc/audit/auditd.conf
sudo systemctl kill auditd -s SIGHUP
chgrp adm /var/log/audit/
systemctl restart auditd
#4.1.4  4.1.4.4 Ensure the audit log directory is 0750 or more restrictive
chmod g-w,o-rwx '$(dirname $( awk -F'=' '/^s*log_files*=s*/ {print $2}' /etc/audit/auditd.conf))'
#4.1.4  4.1.4.5 Ensure audit configuration files are 640 or more restrictive
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod u-x,g-wx,o-rwx {} +
#4.1.4  4.1.4.6 Ensure audit configuration files are owned by root
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} +
#4.1.4  4.1.4.7 Ensure audit configuration files belong to group root
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} +
#4.1.4  4.1.4.8 Ensure audit tools are 755 or more restrictive
chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
#4.1.4  4.1.4.9 Ensure audit tools are owned by root
chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
#4.1.4  4.1.4.10        Ensure audit tools belong to group root
chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
chown root:root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
#4.1.4  4.1.4.11        Ensure cryptographic mechanisms are used to protect the integrity of audit tools
echo "/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
echo "/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
echo "/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
echo "/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
echo "/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
echo "/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
#4.2            Configure Logging
#4.2    4.2.3   Ensure all logfiles have appropriate permissions and ownership
find /var/log -type f -exec chmod g-wx,o-rwx {} +
find /var/log -type f -exec chmod g-wx,o-rwx '{}' + -o -type d -exec chmod g-w,o-rwx '{}' +
#4.2.1          Configure journald
#4.2.1  4.2.1.2 Ensure journald service is enabled
systemctl restart systemd-journald.service
systemctl enable systemd-journald.service
journalctl --flush
#4.2.1  4.2.1.3 Ensure journald is configured to compress large log files
sed -i 's/#Compress.*/Compress=yes/' /etc/systemd/journald.conf
systemctl restart systemd-journald.service
#4.2.1  4.2.1.4 Ensure journald is configured to write logfiles to persistent disk
sed -i 's/#Storage.*/Storage=persistent/' /etc/systemd/journald.conf
systemctl restart systemd-journald.service
#4.2.1  4.2.1.5 Ensure journald is not configured to send logs to rsyslog
sed -i 's/#ForwardToSyslog.*/ForwardToSyslog=yes/' /etc/systemd/journald.conf
systemctl restart systemd-journald.service
#4.2.1  4.2.1.6 Ensure journald log rotation is configured per site policy
echo "Not Applicable"
#4.2.1  4.2.1.7 Ensure journald default file permissions configured
echo "Not Applicable"
#4.2.1.1                Ensure journald is configured to send logs to a remote log host
#4.2.1.1        4.2.1.1.1       Ensure systemd-journal-remote is installed
apt install systemd-journal-remote -y
#4.2.1.1        4.2.1.1.2       Ensure systemd-journal-remote is configured
echo "Not Applicable"
#4.2.1.1        4.2.1.1.3       Ensure systemd-journal-remote is enabled
systemctl --now enable systemd-journal-upload.service
#4.2.1.1        4.2.1.1.4       Ensure journald is not configured to recieve logs from a remote client
systemctl --now disable systemd-journal-remote.socket
#4.2.2          Configure rsyslog
#4.2.2  4.2.2.1 Ensure rsyslog is installed
apt install rsyslog -y
#4.2.2  4.2.2.2 Ensure rsyslog service is enabled
systemctl --now enable rsyslog
#4.2.2  4.2.2.3 Ensure journald is configured to send logs to rsyslog
sed -i 's/#ForwardToSyslog.*/ForwardToSyslog=yes/' /etc/systemd/journald.conf
systemctl restart systemd-journald.service
#4.2.2  4.2.2.4 Ensure rsyslog default file permissions are configured
grep ^\$FileCreateMode /etc/rsyslog.conf
#4.2.2  4.2.2.5 Ensure logging is configured
systemctl restart rsyslog
#4.2.2  4.2.2.6 Ensure rsyslog is configured to send logs to a remote log host
systemctl restart rsyslog
#4.2.2  4.2.2.7 Ensure rsyslog is not configured to receive logs from a remote client
systemctl restart rsyslog
#5              Access, Authentication and Authorization
#5.1            Configure time-based job schedulers
#5.1    5.1.1   Ensure cron daemon is enabled and running
systemctl --now enable cron
#5.1    5.1.2   Ensure permissions on /etc/crontab are configured
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
#5.1    5.1.3   Ensure permissions on /etc/cron.hourly are configured
chown root:root /etc/cron.hourly/
chmod og-rwx /etc/cron.hourly/
#5.1    5.1.4   Ensure permissions on /etc/cron.daily are configured
chown root:root /etc/cron.daily/
chmod og-rwx /etc/cron.daily/
#5.1    5.1.5   Ensure permissions on /etc/cron.weekly are configured
chown root:root /etc/cron.weekly/
chmod og-rwx /etc/cron.weekly/
#5.1    5.1.6   Ensure permissions on /etc/cron.monthly are configured
chown root:root /etc/cron.monthly/
chmod og-rwx /etc/cron.monthly/
#5.1    5.1.7   Ensure permissions on /etc/cron.d are configured
chown root:root /etc/cron.d/
chmod og-rwx /etc/cron.d/
#5.1    5.1.8   Ensure cron is restricted to authorized users
rm -rf /etc/cron.deny
touch /etc/cron.allow
chmod g-wx,o-rwx /etc/cron.allow
chown root:root /etc/cron.allow
#5.1    5.1.9   Ensure at is restricted to authorized users
rm -rf /etc/at.deny
touch /etc/at.allow
chmod g-wx,o-rwx /etc/at.allow
chown root:root /etc/at.allow
#5.2            Configure SSH Server
#5.2    5.2.1   Ensure permissions on /etc/ssh/sshd_config are configured
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
#5.2    5.2.2   Ensure permissions on SSH private host key files are configured
#5.2    5.2.3   Ensure permissions on SSH public host key files are configured
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-wx {} ;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} ;
#5.2    5.2.4   Ensure SSH access is limited
echo "Not Applicable in our environment - Managed BY IDM"
#5.2    5.2.5   Ensure SSH LogLevel is appropriate
sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
#5.2    5.2.6   Ensure SSH PAM is enabled
sed -i 's/UsePAM.*/UsePAM=yes/' /etc/ssh/sshd_config
#5.2    5.2.7   Ensure SSH root login is disabled
sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
#5.2    5.2.8   Ensure SSH HostbasedAuthentication is disabled
sed -i 's/#HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config
#5.2    5.2.9   Ensure SSH PermitEmptyPasswords is disabled
sed -i 's/#PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
#5.2    5.2.10  Ensure SSH PermitUserEnvironment is disabled
sed -i 's/#PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config
#5.2    5.2.11  Ensure SSH IgnoreRhosts is enabled
sed -i 's/#IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config
#5.2    5.2.13  Ensure only strong Ciphers are used
echo "Ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com" >> /etc/ssh/sshd_config
#5.2    5.2.14  Ensure only strong MAC algorithms are used
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
#5.2    5.2.15  Ensure only strong Key Exchange algorithms are used
echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"  >> /etc/ssh/sshd_config
#5.2    5.2.17  Ensure SSH warning banner is configured
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
#5.2    5.2.18  Ensure SSH MaxAuthTries is set to 4 or less
sed -i 's/#MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config
#5.2    5.2.19  Ensure SSH MaxStartups is configured
sed -i 's/#MaxStartups.*/MaxStartups 10:30:60/' /etc/ssh/sshd_config
#5.2    5.2.20  Ensure SSH MaxSessions is set to 10 or less
sed -i 's/#MaxSessions.*/MaxSessions 10/' /etc/ssh/sshd_config
#5.2    5.2.21  Ensure SSH LoginGraceTime is set to one minute or less
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 1m/' /etc/ssh/sshd_config
#5.2    5.2.22  Ensure SSH Idle Timeout Interval is configured
sed -i 's/#ClientAliveInterval.*/ClientAliveInterval 15/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax.*/ClientAliveCountMax 3/' /etc/ssh/sshd_config
#5.3            Configure privilege escalation
#5.3    5.3.1   Ensure sudo is installed
apt install sudo -y
#5.3    5.3.2   Ensure sudo commands use pty
echo "remediated with the patching "
#5.3    5.3.3   Ensure sudo log file exists
echo "Defaults logfile=/var/log/sudo.log" >> /etc/sudoers
#5.3    5.3.5   Ensure re-authentication for privilege escalation is not disabled globally
echo "remediated with the patching "
#5.3    5.3.6   Ensure sudo authentication timeout is configured correctly
echo "Defaults timestamp_timeout=15" >> /etc/sudoers
echo "Defaults env_reset" >> /etc/sudoers
#5.3    5.3.7   Ensure access to the su command is restricted
groupadd sugroup
echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su
#5.4            Configure PAM
#5.4    5.4.1   Ensure password creation requirements are configured
apt install libpam-pwquality -y
sed -i 's/# minlen = 8/minlen = 15/' /etc/security/pwquality.conf
sed -i 's/# minclass = 0/minclass=4/' /etc/security/pwquality.conf
sed -i 's/# dcredit = 0/dcredit=-1/' /etc/security/pwquality.conf
sed -i 's/# ucredit = 0/ucredit=-1/' /etc/security/pwquality.conf
sed -i 's/# ocredit = 0/ocredit=-1/' /etc/security/pwquality.conf
sed -i 's/# lcredit = 0/lcredit=-1/' /etc/security/pwquality.conf
#5.4    5.4.2   Ensure lockout for failed password attempts is configured
echo "account required pam_faillock.so" >> /etc/pam.d/common-account
sed -i 's/# deny = 3/deny = 4/' /etc/security/faillock.conf
sed -i 's/# fail_interval = 900/fail_interval = 900/' /etc/security/faillock.conf
sed -i 's/# unlock_time = 600/unlock_time = 300/' /etc/security/faillock.conf
#5.4    5.4.3   Ensure password reuse is limited
echo "password        [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass yescrypt remember=5"  >> /etc/pam.d/common-password
#5.4    5.4.4   Ensure password hashing algorithm is up to date with the latest standards
sed -i 's/ENCRYPT_METHOD.*/ENCRYPT_METHOD yescrypt/' /etc/login.defs
#5.4    5.4.5   Ensure all current passwords uses the configured hashing algorithm
echo "password sufficient pam_unix.so sha512" >> /etc/pam.d/password-auth
touch etc/pam.d/system-auth
echo "password sufficient pam_unix.so sha512" >> etc/pam.d/system-auth
#5.5            User Accounts and Environment
#5.5    5.5.2   Ensure system accounts are secured
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}'
#5.5    5.5.3   Ensure default group for the root account is GID 0
usermod -g 0 root
#5.5    5.5.4   Ensure default user umask is 027 or more restrictive
grep -RPi '(^|^[^#]*)s*umasks+([0-7][0-7][01][0-7]b|[0-7][0-7][0-7][0-6]b|[0-7][01][0-7]b|[0-7][0-7][0-6]b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(,o=[rwx]{0,3})?b)' /etc/login.defs /etc/profile* /etc/bash.bashrc*
sed -i 's/UMASK.*/UMASK    027/' /etc/login.defs
sed -i 's/USERGROUPS_ENAB yes/USERGROUPS_ENAB no/' /etc/login.defs
#5.5    5.5.5   Ensure default user shell timeout is 900 seconds or less
touch /etc/profile.d/tmout.sh
echo "readonly TMOUT=900 ; export TMOUT" >> /etc/profile.d/tmout.sh
#5.5.1          Set Shadow Password Suite Parameters
#5.5.1  5.5.1.1 Ensure minimum days between password changes is  configured
sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
#5.5.1  5.5.1.2 Ensure password expiration is 365 days or less
sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
#5.5.1  5.5.1.3 Ensure password expiration warning days is 7 or more
sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
#5.5.1  5.5.1.4 Ensure inactive password lock is 30 days or less
useradd -D -f 30
sed -i 's/# INACTIVE.*/INACTIVE=30/' /etc/default/useradd
#5.5.1  5.5.1.5 Ensure all users last password change date is in the past
echo "remediated with the patching "
#6              System Maintenance
#6.1            System File Permissions
#6.1    6.1.1   Ensure permissions on /etc/passwd are configured
chown root:root /etc/passwd
chmod u-x,go-wx /etc/passwd
#6.1    6.1.2   Ensure permissions on /etc/passwd- are configured
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-
#6.1    6.1.3   Ensure permissions on /etc/group are configured
chown root:root /etc/group
chmod u-x,go-wx /etc/group
#6.1    6.1.4   Ensure permissions on /etc/group- are configured
chown root:root /etc/group-
chmod u-x,go-wx /etc/group-
#6.1    6.1.5   Ensure permissions on /etc/shadow are configured
chown root:root /etc/shadow
chown root:shadow /etc/shadow
chmod u-x,g-wx,o-rwx /etc/shadow
#6.1    6.1.6   Ensure permissions on /etc/shadow- are configured
chown root:root /etc/shadow-
chown root:shadow /etc/shadow-
chmod u-x,g-wx,o-rwx /etc/shadow-
#6.1    6.1.7   Ensure permissions on /etc/gshadow are configured
chown root:root /etc/gshadow
chown root:shadow /etc/gshadow
chmod u-x,g-wx,o-rwx /etc/gshadow
#6.1    6.1.8   Ensure permissions on /etc/gshadow- are configured
chown root:root /etc/gshadow-
chown root:shadow /etc/gshadow-
chmod u-x,g-wx,o-rwx /etc/gshadow-
#6.1    6.1.9   Ensure no world writable files exist
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002
find / -xdev -type f -perm -0002
chmod 0600 /var/lib/private/systemd/journal-upload/
chown root:root /var/lib/private/systemd/journal-upload/
#6.1    6.1.10  Ensure no unowned files or directories exist
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser
find / -xdev -nouser
chmod 0600 /var/lib/private/systemd/journal-upload/
#6.1    6.1.11  Ensure no ungrouped files or directories exist
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup
find / -xdev -nogroup
chown root:root /var/lib/private/systemd/journal-upload/
mkdir -p /etc/scripts/
touch /etc/scripts/set-journal-upload.sh
chmod +x /etc/scripts/set-journal-upload.sh
echo "chmod 0600 /var/lib/private/systemd/journal-upload/" >> /etc/scripts/set-journal-upload.sh
echo "chown root:root /var/lib/private/systemd/journal-upload" >> /etc/scripts/set-journal-upload.sh
crontab -l | { cat; echo "@reboot /etc/scripts/set-journal-upload.sh"; } | crontab -
#6.1    6.1.12  Audit SUID executables
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000
find / -xdev -type f -perm -4000
#6.1    6.1.13  Audit SGID executables
find / -xdev -perm +o=w ! \( -type d -perm +o=t \) ! -type l -print
find / -xdev -perm +o=w ! \( -type d -perm +o=t \) ! -type l -ok chmod -v o-w {} \;
#6.2            Local User and Group Settings
#6.2    6.2.1   Ensure accounts in /etc/passwd use shadowed passwords
sed -e 's/^([a-zA-Z0-9_]*):[^:]*:/1:x:/' -i /etc/passwd
#6.2    6.2.2   Ensure /etc/shadow password fields are not empty
echo "remediated with the patching "
#6.2    6.2.3   Ensure all groups in /etc/passwd exist in /etc/group
echo "remediated with the patching "
#6.2    6.2.4   Ensure shadow group is empty
echo "remediated with the patching "
sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+$)/1/' /etc/group
#6.2    6.2.5   Ensure no duplicate UIDs exist
echo "remediated with the patching "
#.2     6.2.6   Ensure no duplicate GIDs exist
echo "remediated with the patching "
#6.2    6.2.7   Ensure no duplicate user names exist
echo "remediated with the patching "
#6.2    6.2.8   Ensure no duplicate group names exist
echo "remediated with the patching "
#6.2    6.2.9   Ensure root PATH Integrity
echo "remediated with the patching "
#6.2    6.2.10  Ensure root is the only UID 0 account
echo "remediated with the patching "
#6.2    6.2.11  Ensure local interactive user home directories exist
echo "remediated with the patching "
#6.2    6.2.12  Ensure local interactive users own their home directories
echo "remediated with the patching "
#6.2    6.2.13  Ensure local interactive user home directories are mode 750 or more restrictive
echo "remediated with the patching "
#6.2    6.2.14  Ensure no local interactive user has .netrc files
echo "remediated with the patching "
#6.2    6.2.15  Ensure no local interactive user has .forward files
echo "remediated with the patching "
#6.2    6.2.16  Ensure no local interactive user has .rhosts files
echo "remediated with the patching "
#6.2    6.2.17  Ensure local interactive user dot files are not group or world writable
echo "remediated with the patching "
