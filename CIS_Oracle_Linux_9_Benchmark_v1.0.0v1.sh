#
##!/usr/bin/env bash
##
## CIS Oracle linux 9 Benchmark v1.0.0 Custom script
## This is the Script For the CIS ubuntu L1-server profile
## Name                          Date        Description
## ------------------------------------------------------------------------------------------------
## Arulpandiyan Durai        11/12/2023   "CIS_Oracle_Linux_9_Benchmark_v1.0.0"
#
## Ensure script is executed in bash
#
##1		Initial Setup
#1	1.9	Ensure updates, patches, and additional security software are installed
dnf update -y
dnf check-update -y
#1	1.10	Ensure system-wide crypto policy is not legacy
update-crypto-policies --set DEFAULT
update-crypto-policies
#1.1		Filesystem Configuration
#1.1	1.1.9	Disable USB Storage
echo "install usb-storage /bin/true" >>  /etc/modprobe.d/usb-storage.conf
echo "blacklist usb-storage" >>  /etc/modprobe.d/usb-storage.conf
modprobe -r usb-storage
#1.1.1		Disable unused filesystems
#1.1.2		Configure /tmp
#1.1.2	1.1.2.1	Ensure /tmp is a separate partition
#1.1.2	1.1.2.2	Ensure nodev option set on /tmp partition
#1.1.2	1.1.2.3	Ensure noexec option set on /tmp partition
#1.1.2	1.1.2.4	Ensure nosuid option set on /tmp partition
systemctl unmask tmp.mount
tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=5G 0 0
#1.1.3		Configure /var
#1.1.3	1.1.3.2	Ensure nodev option set on /var partition
#1.1.3	1.1.3.3	Ensure nosuid option set on /var partition
echo "Applied with the /root patirion config"
#1.1.4		Configure /var/tmp
#1.1.4	1.1.4.2	Ensure noexec option set on /var/tmp partition
#1.1.4	1.1.4.3	Ensure nosuid option set on /var/tmp partition
#1.1.4	1.1.4.4	Ensure nodev option set on /var/tmp partition
echo "Applied with the /root patirion config"
#1.1.5		Configure /var/log
#1.1.5	1.1.5.2	Ensure nodev option set on /var/log partition
#1.1.5	1.1.5.3	Ensure noexec option set on /var/log partition
#1.1.5	1.1.5.4	Ensure nosuid option set on /var/log partition
echo "Applied with the /root patirion config"
#1.1.6		Configure /var/log/audit
#1.1.6	1.1.6.2	Ensure noexec option set on /var/log/audit partition
#1.1.6	1.1.6.3	Ensure nodev option set on /var/log/audit partition
#1.1.6	1.1.6.4	Ensure nosuid option set on /var/log/audit partition
echo "Applied with the /root patirion config"
#1.1.7		Configure /home
#1.1.7	1.1.7.2	Ensure nodev option set on /home partition
#1.1.7	1.1.7.3	Ensure nosuid option set on /home partition
echo "Applied with the /root patirion config"
#1.1.8		Configure /dev/shm
#1.1.8	1.1.8.1	Ensure /dev/shm is a separate partition
#1.1.8	1.1.8.2	Ensure nodev option set on /dev/shm partition
#1.1.8	1.1.8.3	Ensure noexec option set on /dev/shm partition
#1.1.8	1.1.8.4	Ensure nosuid option set on /dev/shm partition
tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0
#1.2		Configure Software Updates
#1.2	1.2.1	Ensure GPG keys are configured
#1.2	1.2.2	Ensure gpgcheck is globally activated
#1.2	1.2.3	Ensure package manager repositories are configured
grep ^gpgcheck /etc/dnf/dnf.conf
sed -i 's/^gpgcheck\s*=\s*.*/gpgcheck=1/' /etc/dnf/dnf.conf
find /etc/yum.repos.d/ -name "*.repo" -exec echo "Checking:" {} \; -exec sed -i 's/^gpgcheck\s*=\s*.*/gpgcheck=1/' {} \;
dnf repolist
#1.3		Filesystem Integrity Checking
#1.3	1.3.1	Ensure AIDE is installed
dnf install aide -y
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
#1.3	1.3.2	Ensure filesystem integrity is regularly checked
crontab -l | { cat; echo "0 5 * * * /usr/sbin/aide --check"; } | crontab -
#1.3	1.3.3	Ensure cryptographic mechanisms are used to protect the integrity of audit tools
echo "/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
echo "/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
echo "/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
echo "/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
echo "/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
echo "/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
#1.4		Secure Boot Settings
#1.4	1.4.1	Ensure bootloader password is set
echo "waiting for the MGMT approval for this Benchmark to applied"
#1.4	1.4.2	Ensure permissions on bootloader config are configured
[ -f /boot/grub2/grub.cfg ] && chown root:root /boot/grub2/grub.cfg
[ -f /boot/grub2/grub.cfg ] && chmod og-rwx /boot/grub2/grub.cfg
[ -f /boot/grub2/grubenv ] && chown root:root /boot/grub2/grubenv
[ -f /boot/grub2/grubenv ] && chmod og-rwx /boot/grub2/grubenv
[ -f /boot/grub2/user.cfg ] && chown root:root /boot/grub2/user.cfg
[ -f /boot/grub2/user.cfg ] && chmod og-rwx /boot/grub2/user.cfg
#1.5		Additional Process Hardening
#1.5	1.5.1	Ensure core dump storage is disabled
sed -i 's/#Storage=external/Storage=none/' /etc/systemd/coredump.conf
#1.5	1.5.2	Ensure core dump backtraces are disabled
sed -i 's/#ProcessSizeMax=2G/ProcessSizeMax=0/' /etc/systemd/coredump.conf
#1.5	1.5.3	Ensure address space layout randomization (ASLR) is enabled
touch /etc/sysctl.d/60-kernel_sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/60-kernel_sysctl.conf
sysctl -w kernel.randomize_va_space=2
#1.6		Mandatory Access Control
#1.6.1		Configure SELinux
#1.6.1	1.6.1.1	Ensure SELinux is installed
dnf install libselinux -y
#1.6.1	1.6.1.2	Ensure SELinux is not disabled in bootloader configuration
grubby --update-kernel ALL --remove-args "selinux=0 enforcing=0"
grep -Prsq -- '\h*([^#\n\r]+\h+)?kernelopts=([^#\n\r]+\h+)?(selinux|enforcing)=0\b' /boot/grub2 /boot/efi && grub2-mkconfig -o "$(grep -Prl -- '\h*([^#\n\r]+\h+)?kernelopts=([^#\n\r]+\h+)?(selinux|enforcing)=0\b' /boot/grub2 /boot/efi)"
#1.6.1	1.6.1.3	Ensure SELinux policy is configured
sed -i 's/SELINUXTYPE=targeted/SELINUXTYPE=targeted/' /etc/selinux/config
#1.6.1	1.6.1.4	Ensure the SELinux mode is not disabled
sed -i 's/SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
setenforce 1
#1.6.1	1.6.1.6	Ensure no unconfined services exist
ps -eZ | grep unconfined_service_t
#1.6.1	1.6.1.7	Ensure SETroubleshoot is not installed
dnf remove setroubleshoot -y
#1.6.1	1.6.1.8	Ensure the MCS Translation Service (mcstrans) is not installed
dnf remove mcstrans -y
#1.7		Command Line Warning Banners
#1.7	1.7.1	Ensure message of the day is configured properly
rm /etc/motd
#1.7	1.7.2	Ensure local login warning banner is configured properly
echo 'This system is the property of Lean Business services. By using this system, you are responsible for all activities performed using your account. You may only access and use the information on this server for authorized purposes. Any unauthorized access or use of this server may result in disciplinary action. You must comply with all applicable laws and regulations, including those related to Cybersecurity Policies.This server is  monitored for security purposes.' > /etc/issue
#1.7	1.7.3	Ensure remote login warning banner is configured properly
echo 'This system is the property of Lean Business services. By using this system, you are responsible for all activities performed using your account. You may only access and use the information on this server for authorized purposes. Any unauthorized access or use of this server may result in disciplinary action. You must comply with all applicable laws and regulations, including those related to Cybersecurity Policies.This server is  monitored for security purposes.' > /etc/issue.net
#1.7	1.7.4	Ensure permissions on /etc/motd are configured
chown root:root /etc/motd 
chmod u-x,go-wx /etc/motd
#1.7	1.7.5	Ensure permissions on /etc/issue are configured
chown root:root /etc/issue 
chmod u-x,go-wx /etc/issue
#1.7	1.7.6	Ensure permissions on /etc/issue.net are configured
chown root:root /etc/issue.net
chmod u-x,go-wx /etc/issue.net
#1.8		GNOME Display Manager
#1.8	1.8.2	Ensure GDM login banner is configured
#1.8	1.8.3	Ensure GDM disable-user-list option is enabled
#1.8	1.8.4	Ensure GDM screen locks when the user is idle
#1.8	1.8.5	Ensure GDM screen locks cannot be overridden
#1.8	1.8.6	Ensure GDM automatic mounting of removable media is disabled
#1.8	1.8.7	Ensure GDM disabling automatic mounting of removable media is not overridden
#1.8	1.8.8	Ensure GDM autorun-never is enabled
#1.8	1.8.9	Ensure GDM autorun-never is not overridden
#1.8	1.8.10	Ensure XDCMP is not enabled
dnf remove gdm3 -y
#2		Services
#2	2.4	Ensure nonessential services listening on the system are removed or masked
ss -plntu
#2.1		Time Synchronization
#2.1	2.1.1	Ensure time synchronization is in use
dnf install chrony -y
#2.1	2.1.2	Ensure chrony is configured
timedatectl set-timezone Asia/Riyadh
echo "server 10.30.192.11 iburst" >> /etc/chrony.conf
echo "server 10.30.192.12 iburst" >> /etc/chrony.conf
echo "server 10.20.196.5  iburst" >> /etc/chrony.conf
echo "server 10.20.196.4  iburst"  >> /etc/chrony.conf
sed -i 's/OPTIONS=""/OPTIONS="u chrony"/'  /etc/sysconfig/chronyd
systemctl try-reload-or-restart chronyd.service
#2.2		Special Purpose Services
#2.2	2.2.2	Ensure Avahi Server is not installed
dnf remove avahi -y
#2.2	2.2.3	Ensure CUPS is not installed
dnf remove cups -y
#2.2	2.2.4	Ensure DHCP Server is not installed
dnf remove dhcp-server -y
#2.2	2.2.5	Ensure DNS Server is not installed
dnf remove bind -y
#2.2	2.2.6	Ensure VSFTP Server is not installed
dnf remove vsftpd -y
#2.2	2.2.7	Ensure TFTP Server is not installed
dnf remove tftp-server -y
#2.2	2.2.8	Ensure a web server is not installed
dnf remove httpd nginx -y
#2.2	2.2.9	Ensure IMAP and POP3 server is not installed
dnf remove dovecot cyrus-imapd -y
#2.2	2.2.10	Ensure Samba is not installed
dnf remove samba -y
#2.2	2.2.11	Ensure HTTP Proxy Server is not installed
dnf remove squid -y
#2.2	2.2.12	Ensure net-snmp is not installed
dnf remove net-snmp -y
#2.2	2.2.13	Ensure telnet-server is not installed
dnf remove telnet-server -y
#2.2	2.2.14	Ensure dnsmasq is not installed
dnf remove dnsmasq -y
#2.2	2.2.15	Ensure mail transfer agent is configured for local-only mode
dnf install postfix -y
sed -i 's/^inet_interfaces*.*/inet_interfaces = loopback-only/' /etc/postfix/main.cf
systemctl restart postfix
#2.2	2.2.16	Ensure nfs-utils is not installed or the  nfs-server service is masked
dnf remove nfs-utils -y
#2.2	2.2.17	Ensure rpcbind is not installed or the  rpcbind services are masked
dnf remove rpcbind -y
#2.2	2.2.18	Ensure rsync-daemon is not installed or the rsyncd service is masked
dnf remove rsync-daemon -y
#2.3		Service Clients
#2.3	2.3.1	Ensure telnet client is not installed
dnf remove telnet -y
#2.3	2.3.2	Ensure LDAP client is not installed
dnf remove openldap-clients -y
#2.3	2.3.3	Ensure TFTP client is not installed
dnf remove tftp -y
#2.3	2.3.4	Ensure FTP client is not installed
dnf remove ftp -y
#3		Network Configuration
#3.1		Disable unused network protocols and devices
#3.1	3.1.1	Ensure IPv6 status is identified
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
#3.1	3.1.2	Ensure wireless interfaces are disabled
{
if command -v nmcli >/dev/null 2>&1 ; then
nmcli radio all off
else
if [ -n '$(find /sys/class/net/*/ -type d -name wireless)' ]; then
mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename '$(readlink -f '$driverdir'/device/driver/module)';done | sort -u)
for dm in $mname; do
echo 'install $dm /bin/true' >> /etc/modprobe.d/disable_wireless.conf
done
fi
fi
}
#3.2		Network Parameters (Host Only)
#3.2	3.2.1	Ensure IP forwarding is disabled
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.route.flush=1
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
sysctl -w net.ipv6.conf.all.forwarding=0
sysctl -w net.ipv6.route.flush=1
#3.2	3.2.2	Ensure packet redirect sending is disabled
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0 
sysctl -w net.ipv4.conf.default.send_redirects=0 
sysctl -w net.ipv4.route.flush=1
#3.3		Network Parameters (Host and Router)
#3.3	3.3.1	Ensure source routed packets are not accepted
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w net.ipv6.route.flush=1
#3.3	3.3.2	Ensure ICMP redirects are not accepted
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
#3.3	3.3.3	Ensure secure ICMP redirects are not accepted
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
#3.3	3.3.4	Ensure suspicious packets are logged
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
#3.3	3.3.5	Ensure broadcast ICMP requests are ignored
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
#3.3	3.3.6	Ensure bogus ICMP responses are ignored
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1
#3.3	3.3.7	Ensure Reverse Path Filtering is enabled
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.conf.all.rp_filter=1 
sysctl -w net.ipv4.conf.default.rp_filter=1 
sysctl -w net.ipv4.route.flush=1
#3.3	3.3.8	Ensure TCP SYN Cookies is enabled
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
#3.3	3.3.9	Ensure IPv6 router advertisements are not accepted
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
#3.4		Configure Host Based Firewall
#3.4.1		Configure a firewall utility
#3.4.1	3.4.1.1	Ensure nftables is installed
dnf install nftables -y
#3.4.1	3.4.1.2	Ensure a single firewall configuration utility is in use
systemctl stop iptables
systemctl stop ip6tables
dnf remove iptables-services -y
#3.4.2		Configure firewall rules
#3.4.2	3.4.2.1	Ensure firewalld default zone is set
{ l_zname="public" # <- Update to local site zone name if desired
l_zone="" 
if systemctl is-enabled firewalld.service | grep -q 'enabled'; then 
l_zone="$(firewall-cmd --get-default-zone)"
if [ "$l_zone" = "$l_zname" ]; then
echo -e "\n - The default zone is set to: \"$l_zone\"\n - No remediation required"
elif [ -n "$l_zone" ]; then
echo -e "\n - The default zone is set to: \"$l_zone\"\n - Updating default zone to: \"l_zname\""
firewall-cmd --set-default-zone="$l_zname" 
else 
echo -e "\n - The default zone is set to: \"$l_zone\"\n - Updating default zone to: \"l_zname\"" 
firewall-cmd --set-default-zone="$l_zname" 
fi 
else 
echo -e "\n - FirewallD is not in use on the system\n - No remediation required" 
fi 
}
#3.4.2	3.4.2.2	Ensure at least one nftables table exists
nft create table inet filter
#3.4.2	3.4.2.3	Ensure nftables base chains exist
echo "LEAN FIrewall policy using Firewalld"
#3.4.2	3.4.2.4	Ensure host based firewall loopback traffic is configured
firewall-cmd --zone=public --permanent --add-port=22/udp
firewall-cmd --zone=public --permanent --add-port=22/tcp
firewall-cmd --zone=public --permanent --add-port=53/udp
firewall-cmd --zone=public --permanent --add-port=53/tcp
firewall-cmd --zone=public --permanent --add-port=80/udp
firewall-cmd --zone=public --permanent --add-port=80/tcp
firewall-cmd --zone=public --permanent --add-port=443/udp
firewall-cmd --zone=public --permanent --add-port=443/tcp
firewall-cmd --zone=public --permanent --add-port=389/udp
firewall-cmd --zone=public --permanent --add-port=389/tcp
firewall-cmd --zone=public --permanent --add-port=88/udp
firewall-cmd --zone=public --permanent --add-port=88/tcp
firewall-cmd --zone=public --permanent --add-port=464/udp
firewall-cmd --zone=public --permanent --add-port=464/tcp
firewall-cmd --zone=public --permanent --add-port=123/udp
firewall-cmd --zone=public --permanent --add-port=123/tcp
firewall-cmd --zone=public --permanent --add-port=749/udp
firewall-cmd --zone=public --permanent --add-port=749/tcp
firewall-cmd --zone=public --permanent --add-port=636/tcp
firewall-cmd --zone=public --permanent --add-port=636/udp
firewall-cmd --zone=public --permanent --add-port=3268/tcp
firewall-cmd --zone=public --permanent --add-port=3269/tcp
firewall-cmd --zone=public --permanent --add-port=135/tcp
firewall-cmd --zone=public --permanent --add-port=9389/tcp
firewall-cmd --zone=public --permanent --add-port=445/tcp
firewall-cmd --zone=public --permanent --add-port=445/udp
firewall-cmd --zone=public --permanent --add-port=137/udp
firewall-cmd --zone=public --permanent --add-port=138/udp
firewall-cmd --zone=public --permanent --add-port=139/udp
firewall-cmd --zone=public --permanent --add-port=49152/tcp
firewall-cmd --zone=public --permanent --add-port=65535/tcp
firewall-cmd --zone=public --permanent --add-port=7070/tcp
firewall-cmd --zone=public --permanent --add-port=7070/udp
firewall-cmd --zone=public --permanent --add-port=139/tcp
firewall-cmd --zone=public --permanent --add-port=8020/tcp
firewall-cmd --zone=public --permanent --add-port=8383/tcp
firewall-cmd --zone=public --permanent --add-port=8027/tcp
firewall-cmd --zone=public --permanent --add-port=8021/tcp
firewall-cmd --zone=public --permanent --add-port=8384/tcp
firewall-cmd --zone=public --permanent --add-port=1024/tcp
firewall-cmd --zone=public --permanent --add-port=161/udp
firewall-cmd --zone=public --permanent --add-port=161/tcp
firewall-cmd --zone=public --permanent --add-port=514/tcp
firewall-cmd --zone=public --permanent --add-port=514/udp
firewall-cmd --zone=public --permanent --add-port=25/tcp
firewall-cmd --zone=public --permanent --add-port=25/udp
firewall-cmd --zone=public --permanent --add-port=23/tcp
firewall-cmd --zone=public --permanent --add-port=23/udp
firewall-cmd --zone=public --permanent --add-port=22/tcp
#3.4.2	3.4.2.5	Ensure firewalld drops unnecessary services and ports
firewall-cmd --remove-service=cockpit
firewall-cmd --remove-port=100/tcp
firewall-cmd --runtime-to-permanent
#3.4.2	3.4.2.6	Ensure nftables established connections are configured
systemctl is-enabled nftables.service | grep -q 'enabled' && nft add rule inet filter input ip protocol tcp ct state established accept
systemctl is-enabled nftables.service | grep -q 'enabled' && nft add rule inet filter input ip protocol udp ct state established accept
systemctl is-enabled nftables.service | grep -q 'enabled' && nft add rule inet filter input ip protocol icmp ct state established accept
#3.4.2	3.4.2.7	Ensure nftables default deny firewall policy
nft chain inet filter input { policy drop \; }
nft chain inet filter forward { policy drop \; }
#4		Logging and Auditing
#4	4.3	Ensure logrotate is configured
#4.1		Configure System Accounting (auditd)
#4.1.1		Ensure auditing is enabled
dnf install audit -y
#4.1.2		Configure Data Retention
grubby --update-kernel ALL --args 'audit=1'
#4.1.3		Configure auditd rules
#4.1.4		Configure auditd file access
#4.2		Configure Logging
#4.2	4.2.3	Ensure all logfiles have appropriate permissions and ownership
find /var/log -type f -exec chmod g-wx,o-rwx {} +
find /var/log -type f -exec chmod g-wx,o-rwx '{}' + -o -type d -exec chmod g-w,o-rwx '{}' +
#4.2.1		Configure rsyslog
#4.2.1	4.2.1.1	Ensure rsyslog is installed
dnf install rsyslog -y
#4.2.1	4.2.1.2	Ensure rsyslog service is enabled
systemctl --now enable rsyslog
#4.2.1	4.2.1.3	Ensure journald is configured to send logs to rsyslog
sed -ri 's/^\s*#ForwardToSyslog=no/ForwardToSyslog=yes/' /etc/systemd/journald.conf
#4.2.1	4.2.1.4	Ensure rsyslog default file permissions are configured
echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf
#4.2.1	4.2.1.5	Ensure logging is configured
echo "*.emerg :omusrmsg:* 
auth,authpriv.* /var/log/secure 
mail.* -/var/log/mail 
mail.info -/var/log/mail.info 
mail.warning -/var/log/mail.warn 
mail.err /var/log/mail.err 
cron.* /var/log/cron 
*.=warning;*.=err -/var/log/warn 
*.crit /var/log/warn 
*.*;mail.none;news.none -/var/log/messages 
local0,local1.* -/var/log/localmessages 
local2,local3.* -/var/log/localmessages 
local4,local5.* -/var/log/localmessages 
local6,local7.* -/var/log/localmessages" >> /etc/rsyslog.conf
systemctl restart rsyslog
#4.2.1	4.2.1.6	Ensure rsyslog is configured to send logs to a remote log host
systemctl restart rsyslog
#4.2.1	4.2.1.7	Ensure rsyslog is not configured to receive logs from a remote client
systemctl restart rsyslog
#4.2.2		Configure journald
#4.2.2	4.2.2.2	Ensure journald service is enabled
dnf install systemd-journal-remote -y
systemctl enable systemd-journald.service
#4.2.2	4.2.2.3	Ensure journald is configured to compress large log files
sed -i 's/#Compress=yes/Compress=yes/' /etc/systemd/journald.conf
#4.2.2	4.2.2.4	Ensure journald is configured to write logfiles to persistent disk
sed -i 's/#Storage.*/Storage=persistent/' /etc/systemd/journald.conf
#4.2.2	4.2.2.5	Ensure journald is not configured to send logs to rsyslog
sed -i 's/#ForwardToSyslog.*/ForwardToSyslog=yes/' /etc/systemd/journald.conf
#4.2.2	4.2.2.6	Ensure journald log rotation is configured per site policy
echo "logrotate configured with the OS"
#4.2.2	4.2.2.7	Ensure journald default file permissions configured
cp -r /usr/lib/tmpfiles.d/systemd.conf /etc/tmpfiles.d/systemd.conf
#4.2.2.1		Ensure journald is configured to send logs to a remote log host
#4.2.2.1	4.2.2.1.1	Ensure systemd-journal-remote is installed
dnf install systemd-journal-remote -y
#4.2.2.1	4.2.2.1.2	Ensure systemd-journal-remote is configured
systemctl restart systemd-journal-upload
#4.2.2.1	4.2.2.1.3	Ensure systemd-journal-remote is enabled
systemctl --now enable systemd-journal-upload.service
#4.2.2.1	4.2.2.1.4	Ensure journald is not configured to receive logs from a remote client
systemctl --now mask systemd-journal-remote.socket
#5		Access, Authentication and Authorization
#5.1		Configure time-based job schedulers
#5.1	5.1.1	Ensure cron daemon is enabled
systemctl --now enable crond
#5.1	5.1.2	Ensure permissions on /etc/crontab are configured
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
#5.1	5.1.3	Ensure permissions on /etc/cron.hourly are configured
chown root:root /etc/cron.hourly/
chmod og-rwx /etc/cron.hourly/
#5.1	5.1.4	Ensure permissions on /etc/cron.daily are configured
chown root:root /etc/cron.daily/
chmod og-rwx /etc/cron.daily/
#5.1	5.1.5	Ensure permissions on /etc/cron.weekly are configured
chown root:root /etc/cron.weekly/
chmod og-rwx /etc/cron.weekly/
#5.1	5.1.6	Ensure permissions on /etc/cron.monthly are configured
chown root:root /etc/cron.monthly/
chmod og-rwx /etc/cron.monthly/
#5.1	5.1.7	Ensure permissions on /etc/cron.d are configured
chown root:root /etc/cron.d/
chmod og-rwx /etc/cron.d/
#5.1	5.1.8	Ensure cron is restricted to authorized users
[ ! -e "/etc/cron.allow" ] && touch /etc/cron.allow
chown root:root /etc/cron.allow
chmod u-x,g-wx,o-rwx /etc/cron.allow
[ -e "/etc/cron.deny" ] && chown root:root /etc/cron.deny
[ -e "/etc/cron.deny" ] && chmod u-x,g-wx,o-rwx /etc/cron.deny
#5.1	5.1.9	Ensure at is restricted to authorized users
grep -Pq -- '^daemon\b' /etc/group && l_group="daemon" || l_group="root"
[ ! -e "/etc/at.allow" ] && touch /etc/at.allow
chown root:"$l_group" /etc/at.allow
chmod u-x,g-wx,o-rwx /etc/at.allow
[ -e "/etc/at.deny" ] && chown root:"$l_group" /etc/at.deny
[ -e "/etc/at.deny" ] && chmod u-x,g-wx,o-rwx /etc/at.deny
#5.2		Configure SSH Server
#5.2	5.2.1	Ensure permissions on /etc/ssh/sshd_config are configured
chmod u-x,og-rwx /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
#5.2	5.2.2	Ensure permissions on SSH private host key files are configured
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,g-wx,o-rwx {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:ssh_keys {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,go-rwx {} \;
#5.2	5.2.3	Ensure permissions on SSH public host key files are configured
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
#5.2	5.2.4	Ensure SSH access is limited
echo "Managed by IDM"
#5.2	5.2.5	Ensure SSH LogLevel is appropriate
sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
#5.2	5.2.6	Ensure SSH PAM is enabled
sed -i 's/UsePAM.*/UsePAM=yes/' /etc/ssh/sshd_config
#5.2	5.2.7	Ensure SSH root login is disabled
sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
#5.2	5.2.8	Ensure SSH HostbasedAuthentication is disabled
sed -i 's/#HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config
#5.2	5.2.9	Ensure SSH PermitEmptyPasswords is disabled
sed -i 's/#PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
#5.2	5.2.10	Ensure SSH PermitUserEnvironment is disabled
sed -i 's/#PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config
#5.2	5.2.11	Ensure SSH IgnoreRhosts is enabled
sed -i 's/#IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config
#5.2	5.2.14	Ensure system-wide crypto policy is not over-ridden
sed -ri "s/^\s*(CRYPTO_POLICY\s*=.*)$/# \1/" /etc/sysconfig/sshd /etc/ssh/sshd_config.d/*.conf
systemctl reload sshd
#5.2	5.2.15	Ensure SSH warning banner is configured
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
#5.2	5.2.16	Ensure SSH MaxAuthTries is set to 4 or less
sed -i 's/#MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config
#5.2	5.2.17	Ensure SSH MaxStartups is configured
sed -i 's/#MaxStartups.*/MaxStartups 10:30:60/' /etc/ssh/sshd_config
#5.2	5.2.18	Ensure SSH MaxSessions is set to 10 or less
sed -i 's/#MaxSessions.*/MaxSessions 10/' /etc/ssh/sshd_config
#5.2	5.2.19	Ensure SSH LoginGraceTime is set to one minute or less
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 1m/' /etc/ssh/sshd_config
#5.2	5.2.20	Ensure SSH Idle Timeout Interval is configured
sed -i 's/#ClientAliveInterval.*/ClientAliveInterval 15/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax.*/ClientAliveCountMax 3/' /etc/ssh/sshd_config
#5.3		Configure privilege escalation
#5.3	5.3.1	Ensure sudo is installed
dnf install sudo -y
#5.3	5.3.2	Ensure sudo commands use pty
echo "Defaults use_pty" >> /etc/sudoers
#5.3	5.3.3	Ensure sudo log file exists
echo "Defaults logfile=/var/log/sudo.log" >> /etc/sudoers
#5.3	5.3.5	Ensure re-authentication for privilege escalation is not disabled globally
echo "Managed by IDM"
#5.3	5.3.6	Ensure sudo authentication timeout is configured correctly
echo "Defaults timestamp_timeout=15" >> /etc/sudoers
echo "Defaults env_reset, timestamp_timeout=15" >> /etc/sudoers
echo "Defaults env_reset" >> /etc/sudoers
#5.3	5.3.7	Ensure access to the su command is restricted
groupadd sugroup
echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su
#5.4		Configure authselect
#5.4	5.4.1	Ensure custom authselect profile is used
authselect create-profile custom-profile -b sssd --symlink-meta
authselect select custom/custom-profile with-sudo with-faillock without-nullok
#5.4	5.4.2	Ensure authselect includes with-faillock
authselect enable-feature with-faillock
authselect apply-changes
#5.5		Configure PAM
#5.5	5.5.1	Ensure password creation requirements are configured
sed -i 's/# minlen = 8/minlen = 14/' /etc/security/pwquality.conf
sed -i 's/# minclass = 0/minclass = 4/' /etc/security/pwquality.conf
printf  "dcredit = -1" "ucredit = -1" "ocredit = -1" "lcredit = -1" > /etc/security/pwquality.conf.d/50-pwcomplexity.conf
#5.5	5.5.2	Ensure lockout for failed password attempts is configured
sed -i 's/# deny*.*/deny = 5/' /etc/security/faillock.conf
sed -i 's/# unlock_time*.*/unlock_time = 900/' /etc/security/faillock.conf
#5.5	5.5.3	Ensure password reuse is limited
sed -ri 's/# remember.*/remember = 24/' /etc/security/pwhistory.conf
#5.5	5.5.4	Ensure password hashing algorithm is SHA-512 or yescrypt
sed -ri 's/^\s*crypt_style.*/crypt_style = sha512/' /etc/libuser.conf
sed -ri 's/^\s*ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
#5.6		User Accounts and Environment
#5.6	5.6.2	Ensure system accounts are secured
echo "This is not applicacable"
#5.6	5.6.3	Ensure default user shell timeout is 900 seconds or less
touch /etc/profile.d/tmout.sh
echo "readonly TMOUT=900 ; export TMOUT" >> /etc/profile.d/tmout.sh
#5.6	5.6.4	Ensure default group for the root account is GID 0
usermod -g 0 root
#5.6	5.6.5	Ensure default user umask is 027 or more restrictive
grep -Psi -- '^\h*umask\h+(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b|[0-7][0-7][0-6]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc
sed -i 's/UMASK.*/UMASK           027/' /etc/login.defs
sed -i 's/USERGROUPS_ENAB yes/USERGROUPS_ENAB no/' /etc/login.defs
#5.6	5.6.6	Ensure root password is set
sudo sh -c 'echo root:hV7Pj1}A2%FnChsO%@3 | chpasswd'
sudo sh -c 'echo opc:hV7Pj1}A2%FnChsO%@3 | chpasswd'
#5.6.1		Set Shadow Password Suite Parameters
#5.6.1	5.6.1.1	Ensure password expiration is 365 days or less
sed -ri 's/^\s*PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
#5.6.1	5.6.1.2	Ensure minimum days between password changes is  configured
sed -ri 's/^\s*PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
#5.6.1	5.6.1.3	Ensure password expiration warning days is 7 or more
sed -ri 's/^\s*PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
#5.6.1	5.6.1.4	Ensure inactive password lock is 30 days or less
useradd -D -f 30
#5.6.1	5.6.1.5	Ensure all users last password change date is in the past
echo "managed by IDM"
#6		System Maintenance
#6.1		System File Permissions
#6.1	6.1.1	Ensure permissions on /etc/passwd are configured
chmod u-x,go-wx /etc/passwd
chown root:root /etc/passwd
#6.1	6.1.2	Ensure permissions on /etc/passwd- are configured
chmod u-x,go-wx /etc/passwd- 
chown root:root /etc/passwd-
#6.1	6.1.3	Ensure permissions on /etc/group are configured
chmod u-x,go-wx /etc/group
chown root:root /etc/group
#6.1	6.1.4	Ensure permissions on /etc/group- are configured
chmod u-x,go-wx /etc/group-
chown root:root /etc/group-
#6.1	6.1.5	Ensure permissions on /etc/shadow are configured
chown root:root /etc/shadow
chmod 0000 /etc/shadow
#6.1	6.1.6	Ensure permissions on /etc/shadow- are configured
chown root:root /etc/shadow- 
chmod 0000 /etc/shadow-
#6.1	6.1.7	Ensure permissions on /etc/gshadow are configured
chown root:root /etc/gshadow 
chmod 0000 /etc/gshadow
#6.1	6.1.8	Ensure permissions on /etc/gshadow- are configured
chown root:root /etc/gshadow- 
chmod 0000 /etc/gshadow-
#6.1	6.1.9	Ensure no world writable files exist
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup
find / -xdev -nogroup
chown root:root /var/lib/private/systemd/journal-upload/
mkdir -p /etc/scripts/
touch /etc/scripts/set-journal-upload.sh
chmod +x /etc/scripts/set-journal-upload.sh
echo "chmod 0600 /var/lib/private/systemd/journal-upload/" >> /etc/scripts/set-journal-upload.sh
echo "chown root:root /var/lib/private/systemd/journal-upload" >> /etc/scripts/set-journal-upload.sh
crontab -l | { cat; echo "@reboot /etc/scripts/set-journal-upload.sh"; } | crontab -
#6.1	6.1.10	Ensure no unowned files or directories exist
echo "Already Applied"
#6.1	6.1.11	Ensure no ungrouped files or directories exist
echo "Already Applied"
#6.1	6.1.12	Ensure sticky bit is set on all world-writable directories
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'
#6.1	6.1.13	Audit SUID executables
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000
find / -xdev -type f -perm -4000
#6.1	6.1.14	Audit SGID executables
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000
find / -xdev -type f -perm -2000
#6.2		Local User and Group Settings
#6.2	6.2.1	Ensure accounts in /etc/passwd use shadowed passwords
sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd
#6.2	6.2.2	Ensure /etc/shadow password fields are not empty
echo "Applied Lean Policy"
#6.2	6.2.3	Ensure all groups in /etc/passwd exist in /etc/group
echo "remediated with the patching "
#6.2	6.2.4	Ensure no duplicate UIDs exist
echo "remediated with the patching "
#6.2	6.2.5	Ensure no duplicate GIDs exist
echo "remediated with the patching "
#6.2	6.2.6	Ensure no duplicate user names exist
echo "remediated with the patching "
#6.2	6.2.7	Ensure no duplicate group names exist
echo "remediated with the patching "
#6.2	6.2.8	Ensure root PATH Integrity
echo "remediated with the patching "
#6.2	6.2.9	Ensure root is the only UID 0 account
echo "remediated with the patching "
#6.2	6.2.10	Ensure local interactive user home directories exist
{ 
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | while read -r user home; do
    if [ ! -d "$home" ]; then 
       echo -e "\n- User \"$user\" home directory \"$home\" doesn't exist\n- creating home directory \"$home\"\n"
       mkdir "$home" 
       chmod g-w,o-wrx "$home"
       chown "$user" "$home"
       fi 
       done
}
#6.2	6.2.11	Ensure local interactive users own their home directories
{
    output="" 
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$" 
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | while read -r user home; do 
    owner="$(stat -L -c "%U" "$home")" 
    if [ "$owner" != "$user" ]; then echo -e "\n- User \"$user\" home directory \"$home\" is owned by user \"$owner\"\n - changing ownership to \"$user\"\n" 
    chown "$user" "$home" 
    fi
    done
}
#6.2	6.2.12	Ensure local interactive user home directories are mode 750 or more restrictive
{ 
    perm_mask='0027' 
    maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )" 
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$" 
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do
    mode=$( stat -L -c '%#a' "$home" ) 
    if [ $(( $mode & $perm_mask )) -gt 0 ]; then 
    echo -e "- modifying User $user home directory: \"$home\"\n- removing excessive permissions from current mode of \"$mode\"" 
    chmod g-w,o-rwx "$home" 
    fi 
    done
     ) 
}
#6.2	6.2.13	Ensure no local interactive user has .netrc files
{
     perm_mask='0177' 
     valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$" 
     awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | while read -r user home; do
      if [ -f "$home/.netrc" ]; then 
      echo -e "\n- User \"$user\" file: \"$home/.netrc\" exists\n - removing file: \"$home/.netrc\"\n" 
      rm -f "$home/.netrc" 
      fi 
      done 
}
#6.2	6.2.14	Ensure no local interactive user has .forward files
{ 
    output="" 
    fname=".forward" 
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$" 
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do 
    if [ -f "$home/$fname" ]; then 
    echo -e "$output\n- User \"$user\" file: \"$home/$fname\" exists\n - removing file: \"$home/$fname\"\n" 
    rm -r "$home/$fname" 
    fi 
    done
     ) 
}
#6.2	6.2.15	Ensure no local interactive user has .rhosts files
{ 
    perm_mask='0177' 
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$" 
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | while read -r user home; do 
    if [ -f "$home/.rhosts" ]; then 
    echo -e "\n- User \"$user\" file: \"$home/.rhosts\" exists\n - removing file: \"$home/.rhosts\"\n" 
    rm -f "$home/.rhosts" 
    fi 
    done 
}
#6.2	6.2.16	Ensure local interactive user dot files are not group or world writable
{ 
    perm_mask='0022' 
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$" 
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | while read -r user home; do 
    find "$home" -type f -name '.*' | while read -r dfile; do 
    mode=$( stat -L -c '%#a' "$dfile" ) if [ $(( $mode & $perm_mask )) -gt 0 ]; then 
    echo -e "\n- Modifying User \"$user\" file: \"$dfile\"\n- removing group and other write permissions" 
    chmod go-w "$dfile" 
    fi 
    done 
    done 
}
############################END OF SCRIPT########################
echo "The script has completed and kindly run the CIS Assesor to get the CIS Benchmark Score."