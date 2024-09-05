
#!/usr/bin/env bash
#
# CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v1.0.0 Custom Script
# This is the Script For the CIS ubuntu L1-server profile
# Name                          Date        Description
# ------------------------------------------------------------------------------------------------
# Arulpandiyan Durai        11/12/2023   "CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v1.0.0"

# Ensure script is executed in bash

#1		Initial Setup
#1.1		Filesystem
#1.1.1		Configure Filesystem Kernel Modules
#1.1.1	1.1.1.1	Ensure cramfs kernel module is not available
echo "install cramfs /bin/true" >>  /etc/modprobe.d/cramfs.conf
echo "blacklist cramfs" >>  /etc/modprobe.d/cramfs.conf
modprobe -r cramfs
#1.1.1	1.1.1.2	Ensure freevxfs kernel module is not available
echo "install freevxfs /bin/true" >>  /etc/modprobe.d/freevxfs.conf
echo "blacklist freevxfs" >>  /etc/modprobe.d/freevxfs.conf
modprobe -r freevxfs
#1.1.1	1.1.1.3	Ensure hfs kernel module is not available
echo "install hfs /bin/true" >>  /etc/modprobe.d/hfs.conf
echo "blacklist hfs" >>  /etc/modprobe.d/hfs.conf
modprobe -r hfs
#1.1.1	1.1.1.4	Ensure hfsplus kernel module is not available
echo "install hfsplus /bin/true" >>  /etc/modprobe.d/hfsplus.conf
echo "blacklist hfsplus" >>  /etc/modprobe.d/hfsplus.conf
modprobe -r hfsplus
#1.1.1	1.1.1.5	Ensure jffs2 kernel module is not available
echo "install jffs2 /bin/true" >>  /etc/modprobe.d/jffs2.conf
echo "blacklist jffs2" >>  /etc/modprobe.d/jffs2.conf
modprobe -r jffs2
#1.1.1	1.1.1.8	Ensure usb-storage kernel module is not available
echo "install usb-storage /bin/true" >>  /etc/modprobe.d/usb-storage.conf
echo "blacklist usb-storage" >>  /etc/modprobe.d/usb-storage.conf
modprobe -r usb-storage
#1.1.2		Configure Filesystem Partitions
#1.1.2.1		Configure /tmp
#1.1.2.1	1.1.2.1.1	Ensure /tmp is a separate partition
#1.1.2.1	1.1.2.1.2	Ensure nodev option set on /tmp partition
#1.1.2.1	1.1.2.1.3	Ensure nosuid option set on /tmp partition
#1.1.2.1	1.1.2.1.4	Ensure noexec option set on /tmp partition
systemctl unmask tmp.mount
echo "tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0" >>  /etc/fstab
mount -o remount /tmp
systemctl daemon-reload
#1.1.2.2		Configure /dev/shm
#1.1.2.2	1.1.2.2.1	Ensure /dev/shm is a separate partition
#1.1.2.2	1.1.2.2.2	Ensure nodev option set on /dev/shm partition
#1.1.2.2	1.1.2.2.3	Ensure nosuid option set on /dev/shm partition
#1.1.2.2	1.1.2.2.4	Ensure noexec option set on /dev/shm partition
echo "Applied with the /root patirion config"
#1.1.2.3		Configure /home
#1.1.2.3	1.1.2.3.2	Ensure nodev option set on /home partition
#1.1.2.3	1.1.2.3.3	Ensure nosuid option set on /home partition
echo "Applied with the /root patirion config"
#1.1.2.4		Configure /var
#1.1.2.4	1.1.2.4.2	Ensure nodev option set on /var partition
#1.1.2.4	1.1.2.4.3	Ensure nosuid option set on /var partition
echo "Applied with the /root patirion config"
#1.1.2.5		Configure /var/tmp
#1.1.2.5	1.1.2.5.2	Ensure nodev option set on /var/tmp partition
#1.1.2.5	1.1.2.5.3	Ensure nosuid option set on /var/tmp partition
#1.1.2.5	1.1.2.5.4	Ensure noexec option set on /var/tmp partition
echo "Applied with the /root patirion config"
#1.1.2.6		Configure /var/log
#1.1.2.6	1.1.2.6.2	Ensure nodev option set on /var/log partition
#1.1.2.6	1.1.2.6.3	Ensure nosuid option set on /var/log partition
#1.1.2.6	1.1.2.6.4	Ensure noexec option set on /var/log partition
echo "Applied with the /root patirion config"
#1.1.2.7		Configure /var/log/audit
#1.1.2.7	1.1.2.7.2	Ensure nodev option set on /var/log/audit partition
#1.1.2.7	1.1.2.7.3	Ensure nosuid option set on /var/log/audit partition
#1.1.2.7	1.1.2.7.4	Ensure noexec option set on /var/log/audit partition
echo "Applied with the /root patirion config"
#1.2		Configure Software and Patch Management
#1.2	1.2.1	Ensure GPG keys are configured
#1.2	1.2.2	Ensure gpgcheck is globally activated
#1.2	1.2.4	Ensure package manager repositories are configured
sed -i 's/^gpgchecks*=s*.*/gpgcheck=1/' /etc/dnf/dnf.conf
find /etc/yum.repos.d/ -name '*.repo' -exec echo 'Checking:' {} \; -exec sed -ri 's/^\s*gpgchecks.*/gpgcheck=1/' {} \;
dnf update -y
#1.2	1.2.5	Ensure updates, patches, and additional security software are installed
dnf update -y
dnf upgrade -y
dnf install unzip -y
dnf install java-1.8.0-openjdk -y
#1.3		Configure Secure Boot Settings
#1.3	1.3.1	Ensure bootloader password is set
echo "Not Applicable on our environment"
#1.3	1.3.2	Ensure permissions on bootloader config are configured
[ -f /boot/grub2/grub.cfg ] && chown root:root /boot/grub2/grub.cfg
[ -f /boot/grub2/grub.cfg ] && chmod og-rwx /boot/grub2/grub.cfg
[ -f /boot/grub2/grubenv ] && chown root:root /boot/grub2/grubenv
[ -f /boot/grub2/grubenv ] && chmod og-rwx /boot/grub2/grubenv
[ -f /boot/grub2/user.cfg ] && chown root:root /boot/grub2/user.cfg
[ -f /boot/grub2/user.cfg ] && chmod og-rwx /boot/grub2/user.cfg
#1.4		Configure Additional Process Hardening
#1.4	1.4.1	Ensure address space layout randomization (ASLR) is enabled
touch /etc/sysctl.d/60-kernel_sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/60-kernel_sysctl.conf
sysctl -w kernel.randomize_va_space=2
#1.4	1.4.2	Ensure ptrace_scope is restricted
echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.d/60-kernel_sysctl.conf
sysctl -w kernel.yama.ptrace_scope=1
#1.4	1.4.3	Ensure core dump backtraces are disabled
sed -i 's/#ProcessSizeMax=2G/ProcessSizeMax=0/' /etc/systemd/coredump.conf
#1.4	1.4.4	Ensure core dump storage is disabled
sed -i 's/#Storage=external/Storage=none/' /etc/systemd/coredump.conf
#1.5		Mandatory Access Control
#1.5.1		Configure SELinux
#1.5.1	1.5.1.1	Ensure SELinux is installed
dnf install libselinux -y
#1.5.1	1.5.1.2	Ensure SELinux is not disabled in bootloader configuration
grubby --update-kernel ALL --remove-args "selinux=0 enforcing=0"
#1.5.1	1.5.1.3	Ensure SELinux policy is configured
sed -i 's/SELINUXTYPE=targeted/SELINUXTYPE=targeted/' /etc/selinux/config
#1.5.1	1.5.1.4	Ensure the SELinux mode is not disabled
sed -i 's/SELINUX=enforcing/SELINUX=enforcing/' /etc/selinux/config
setenforce 1
#1.5.1	1.5.1.6	Ensure no unconfined services exist
ps -eZ | grep unconfined_service_t
#1.5.1	1.5.1.7	Ensure the MCS Translation Service (mcstrans) is not installed
dnf remove mcstrans -y
#1.5.1	1.5.1.8	Ensure SETroubleshoot is not installed
dnf remove setroubleshoot -y
#1.6		Configure system wide crypto policy
#1.6	1.6.1	Ensure system wide crypto policy is not set to legacy
update-crypto-policies --set DEFAULT
update-crypto-policies
#1.6	1.6.2	Ensure system wide crypto policy disables sha1 hash and signature support
echo -e "# This is a subpolicy dropping the SHA1 hash and signature support\nhash = -SHA1\nsign = -*-SHA1\nsha1_in_certs = 0" > /etc/crypto-policies/policies/modules/NO-SHA1.pmod
update-crypto-policies --set DEFAULT:NO-SHA1
#1.6	1.6.3	Ensure system wide crypto policy disables cbc for ssh
echo -e "# This is a subpolicy to disable all CBC mode ciphers\n# for the SSH protocol (libssh and OpenSSH)\ncipher@SSH = -*-CBC" > /etc/crypto-policies/policies/modules/NO-SSHCBC.pmod
update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC
#1.6	1.6.4	Ensure system wide crypto policy disables macs less than 128 bits
echo -e "# This is a subpolicy to disable weak macs\nmac = -*-64" > /etc/crypto-policies/policies/modules/NO-WEAKMAC.pmod
update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC:NO-WEAKMAC
#1.7		Configure Command Line Warning Banners
#1.7	1.7.1	Ensure message of the day is configured properly
rm /etc/motd
#1.7	1.7.2	Ensure local login warning banner is configured properly
echo 'This system is the property of Lean Business services. By using this system, you are responsible for all activities performed using your account. You may only access and use the information on this server for authorized purposes. Any unauthorized access or use of this server may result in disciplinary action. You must comply with all applicable laws and regulations, including those related to Cybersecurity Policies.This server is  monitored for security purposes.' > /etc/issue
#1.7	1.7.3	Ensure remote login warning banner is configured properly
echo 'This system is the property of Lean Business services. By using this system, you are responsible for all activities performed using your account. You may only access and use the information on this server for authorized purposes. Any unauthorized access or use of this server may result in disciplinary action. You must comply with all applicable laws and regulations, including those related to Cybersecurity Policies.This server is  monitored for security purposes.' > /etc/issue.net
#1.7	1.7.4	Ensure access to /etc/motd is configured
chown root:root $(readlink -e /etc/motd)
chmod u-x,go-wx $(readlink -e /etc/motd)
rm -rf /etc/motd
#1.7	1.7.5	Ensure access to /etc/issue is configured
chown root:root $(readlink -e /etc/issue)
chmod u-x,go-wx $(readlink -e /etc/issue)
#1.7	1.7.6	Ensure access to /etc/issue.net is configured
chown root:root $(readlink -e /etc/issue.net)
chmod u-x,go-wx $(readlink -e /etc/issue.net)
#1.8		Configure GNOME Display Manager
#1.8	1.8.2	Ensure GDM login banner is configured
#1.8	1.8.3	Ensure GDM disable-user-list option is enabled
#1.8	1.8.4	Ensure GDM screen locks when the user is idle
#1.8	1.8.5	Ensure GDM screen locks cannot be overridden
#1.8	1.8.6	Ensure GDM automatic mounting of removable media is disabled
#1.8	1.8.7	Ensure GDM disabling automatic mounting of removable media is not overridden
#1.8	1.8.8	Ensure GDM autorun-never is enabled
#1.8	1.8.9	Ensure GDM autorun-never is not overridden
#1.8	1.8.10	Ensure XDMCP is not enabled
dnf remove gdm3 -y
#2		Services
#2.1		Configure Time Synchronization
#2.1	2.1.1	Ensure time synchronization is in use
dnf install chrony -y
#2.1	2.1.2	Ensure chrony is configured
timedatectl set-timezone Asia/Riyadh
echo "server 10.30.192.11 iburst" >> /etc/chrony.conf
echo "server 10.30.192.12 iburst" >> /etc/chrony.conf
echo "server 10.20.196.5  iburst" >> /etc/chrony.conf
echo "server 10.20.196.4  iburst"  >> /etc/chrony.conf
#2.1	2.1.3	Ensure chrony is not run as the root user
sed -i 's/OPTIONS=""/OPTIONS="u chrony"/'  /etc/sysconfig/chronyd
systemctl try-reload-or-restart chronyd.service
#2.2		Configure Special Purpose Services
#2.2	2.2.1	Ensure autofs services are not in use
dnf remove autofs -y
#2.2	2.2.2	Ensure avahi daemon services are not in use
dnf remove avahi -y
#2.2	2.2.3	Ensure dhcp server services are not in use
dnf remove dhcp-server -y
#2.2	2.2.4	Ensure dns server services are not in use
dnf remove bind -y
#2.2	2.2.5	Ensure dnsmasq services are not in use
dnf remove dnsmasq -y
#2.2	2.2.6	Ensure samba file server services are not in use
dnf remove samba -y
#2.2	2.2.7	Ensure ftp server services are not in use
dnf remove vsftpd -y
#2.2	2.2.8	Ensure message access server services are not in use
dnf remove dovecot cyrus-imapd -y
#2.2	2.2.9	Ensure network file system services are not in use
dnf remove nfs-utils -y
#2.2	2.2.10	Ensure nis server services are not in use
dnf remove ypserv -y
#2.2	2.2.11	Ensure print server services are not in use
dnf remove cups -y
#2.2	2.2.12	Ensure rpcbind services are not in use
dnf remove rpcbind -y
#2.2	2.2.13	Ensure rsync services are not in use
dnf remove rsync-daemon -y
#2.2	2.2.14	Ensure snmp services are not in use
dnf remove net-snmp -y
#2.2	2.2.15	Ensure telnet server services are not in use
dnf remove telnet-server -y
#2.2	2.2.16	Ensure tftp server services are not in use
dnf remove tftp-server -y
#2.2	2.2.17	Ensure web proxy server services are not in use
dnf remove squid -y
#2.2	2.2.18	Ensure web server services are not in use
dnf remove httpd nginx -y
#2.2	2.2.19	Ensure xinetd services are not in use
dnf remove xinetd -y
#2.2	2.2.21	Ensure mail transfer agents are configured for local-only mode
dnf install postfix -y
sed -i 's/^inet_interfaces*.*/inet_interfaces = loopback-only/' /etc/postfix/main.cf
systemctl restart postfix
#2.2	2.2.22	Ensure only approved services are listening on a network interface
echo "Remediated applied above the settings"
#2.3		Configure Service Clients
#2.3	2.3.1	Ensure ftp client is not installed
dnf remove ftp -y
#2.3	2.3.3	Ensure nis client is not installed
dnf remove ypbind -y
#2.3	2.3.4	Ensure telnet client is not installed
dnf remove telnet -y
#2.3	2.3.5	Ensure tftp client is not installed
dnf remove tftp -y
#3		Network
#3.1		Configure Network Devices
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
#3.1	3.1.3	Ensure bluetooth services are not in use
dnf remove bluez -y
#3.2		Configure Network Kernel Modules
#3.3		Configure Network Kernel Parameters
#3.3	3.3.1	Ensure ip forwarding is disabled
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.route.flush=1
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
sysctl -w net.ipv6.conf.all.forwarding=0
sysctl -w net.ipv6.route.flush=1
#3.3	3.3.2	Ensure packet redirect sending is disabled
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0 
sysctl -w net.ipv4.conf.default.send_redirects=0 
sysctl -w net.ipv4.route.flush=1
#3.3	3.3.3	Ensure bogus icmp responses are ignored
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1
#3.3	3.3.4	Ensure broadcast icmp requests are ignored
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
#3.3	3.3.5	Ensure icmp redirects are not accepted
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
#3.3	3.3.6	Ensure secure icmp redirects are not accepted
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
#3.3	3.3.7	Ensure reverse path filtering is enabled
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
#3.3	3.3.8	Ensure source routed packets are not accepted
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
#3.3	3.3.9	Ensure suspicious packets are logged
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
#3.3	3.3.10	Ensure tcp syn cookies is enabled
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
#3.3	3.3.11	Ensure ipv6 router advertisements are not accepted
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
#3.4.2	3.4.2.1	Ensure nftables base chains exist
dnf install firewalld -y
systemctl start firewalld
systemctl enable firewalld
echo "LEAN FIrewall policy using Firewalld"
#3.4.2	3.4.2.2	Ensure host based firewall loopback traffic is configured
firewall-cmd --zone=public --permanent --add-port=22/udp
firewall-cmd --zone=public --permanent --add-port=22/tcp
firewall-cmd --zone=public --permanent --add-port=53/udp
firewall-cmd --zone=public --permanent --add-port=53/tcp
firewall-cmd --zone=public --permanent --add-port=80/udp
firewall-cmd --zone=public --permanent --add-port=80/tcp
firewall-cmd --zone=public --permanent --add-port=443/udp
firewall-cmd --zone=public --permanent --add-port=443/tcp
#3.4.2	3.4.2.3	Ensure firewalld drops unnecessary services and ports
firewall-cmd --remove-service=cockpit
firewall-cmd --remove-port=100/tcp
firewall-cmd --runtime-to-permanent
#3.4.2	3.4.2.4	Ensure nftables established connections are configured
systemctl is-enabled nftables.service | grep -q 'enabled' && nft add rule inet filter input ip protocol tcp ct state established accept
systemctl is-enabled nftables.service | grep -q 'enabled' && nft add rule inet filter input ip protocol udp ct state established accept
systemctl is-enabled nftables.service | grep -q 'enabled' && nft add rule inet filter input ip protocol icmp ct state established accept
#3.4.2	3.4.2.5	Ensure nftables default deny firewall policy
nft chain inet filter input { policy drop \; }
nft chain inet filter forward { policy drop \; }
#4		Access, Authentication and Authorization
#4.1		Configure job schedulers
#4.1.1		Configure cron
#4.1.1	4.1.1.1	Ensure cron daemon is enabled and active
systemctl unmask crond
systemctl --now enable crond
#4.1.1	4.1.1.2	Ensure permissions on /etc/crontab are configured
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
#4.1.1	4.1.1.3	Ensure permissions on /etc/cron.hourly are configured
chown root:root /etc/cron.hourly/
chmod og-rwx /etc/cron.hourly/
#4.1.1	4.1.1.4	Ensure permissions on /etc/cron.daily are configured
chown root:root /etc/cron.daily/
chmod og-rwx /etc/cron.daily/
#4.1.1	4.1.1.5	Ensure permissions on /etc/cron.weekly are configured
chown root:root /etc/cron.weekly/
chmod og-rwx /etc/cron.weekly/
#4.1.1	4.1.1.6	Ensure permissions on /etc/cron.monthly are configured
chown root:root /etc/cron.monthly/
chmod og-rwx /etc/cron.monthly/
#4.1.1	4.1.1.7	Ensure permissions on /etc/cron.d are configured
chown root:root /etc/cron.d/
chmod og-rwx /etc/cron.d/
#4.1.1	4.1.1.8	Ensure crontab is restricted to authorized users
[ ! -e "/etc/cron.allow" ] && touch /etc/cron.allow
chown root:root /etc/cron.allow
chmod u-x,g-wx,o-rwx /etc/cron.allow
[ -e "/etc/cron.deny" ] && chown root:root /etc/cron.deny
[ -e "/etc/cron.deny" ] && chmod u-x,g-wx,o-rwx /etc/cron.deny
#4.1.2		Configure at
#4.1.2	4.1.2.1	Ensure at is restricted to authorized users
grep -Pq -- '^daemon\b' /etc/group && l_group="daemon" || l_group="root"
[ ! -e "/etc/at.allow" ] && touch /etc/at.allow
chown root:"$l_group" /etc/at.allow
chmod u-x,g-wx,o-rwx /etc/at.allow
[ -e "/etc/at.deny" ] && chown root:"$l_group" /etc/at.deny
[ -e "/etc/at.deny" ] && chmod u-x,g-wx,o-rwx /etc/at.deny
#4.2		Configure SSH Server
#4.2	4.2.1	Ensure permissions on /etc/ssh/sshd_config are configured
chmod u-x,og-rwx /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
#4.2	4.2.2	Ensure permissions on SSH private host key files are configured
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,g-wx,o-rwx {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:ssh_keys {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,go-rwx {} \;
#4.2	4.2.3	Ensure permissions on SSH public host key files are configured
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
#4.2	4.2.4	Ensure sshd access is configured
echo "Managed by IDM"
#4.2	4.2.5	Ensure sshd Banner is configured
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
#4.2	4.2.6	Ensure sshd Ciphers are configured
echo "Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se" >> /etc/ssh/sshd_config
#4.2	4.2.7	Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured
sed -i 's/#ClientAliveInterval.*/ClientAliveInterval 15/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax.*/ClientAliveCountMax 3/' /etc/ssh/sshd_config
#4.2	4.2.9	Ensure sshd HostbasedAuthentication is disabled
sed -i 's/#HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config
#4.2	4.2.10	Ensure sshd IgnoreRhosts is enabled
sed -i 's/#IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config
#4.2	4.2.11	Ensure sshd KexAlgorithms is configured
echo "KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1" >> /etc/ssh/sshd_config
#4.2	4.2.12	Ensure sshd LoginGraceTime is configured
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 1m/' /etc/ssh/sshd_config
#4.2	4.2.13	Ensure sshd LogLevel is configured
sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
#4.2	4.2.14	Ensure sshd MACs are configured
echo "MACs -hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com" >> /etc/ssh/sshd_config
#4.2	4.2.15	Ensure sshd MaxAuthTries is configured
sed -i 's/#MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config
#4.2	4.2.16	Ensure sshd MaxSessions is configured
sed -i 's/#MaxSessions.*/MaxSessions 10/' /etc/ssh/sshd_config
#4.2	4.2.17	Ensure sshd MaxStartups is configured
sed -i 's/#MaxStartups.*/MaxStartups 10:30:60/' /etc/ssh/sshd_config
#4.2	4.2.18	Ensure sshd PermitEmptyPasswords is disabled
sed -i 's/#PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
#4.2	4.2.19	Ensure sshd PermitRootLogin is disabled
sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
#4.2	4.2.20	Ensure sshd PermitUserEnvironment is disabled
sed -i 's/#PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config
#4.2	4.2.21	Ensure sshd UsePAM is enabled
sed -i 's/UsePAM.*/UsePAM=yes/' /etc/ssh/sshd_config
#4.2	4.2.22	Ensure sshd crypto_policy is not set
sed -ri "s/^\s*(CRYPTO_POLICY\s*=.*)$/# \1/" /etc/sysconfig/sshd
systemctl reload sshd
#4.3		Configure privilege escalation
#4.3	4.3.1	Ensure sudo is installed
dnf install sudo -y
#4.3	4.3.2	Ensure sudo commands use pty
echo "Defaults use_pty" >> /etc/sudoers
#4.3	4.3.3	Ensure sudo log file exists
echo "Defaults logfile=/var/log/sudo.log" >> /etc/sudoers
#4.3	4.3.5	Ensure re-authentication for privilege escalation is not disabled globally
echo "Managed by IDM"
#4.3	4.3.6	Ensure sudo authentication timeout is configured correctly
echo "Defaults timestamp_timeout=15" >> /etc/sudoers
echo "Defaults env_reset, timestamp_timeout=15" >> /etc/sudoers
echo "Defaults env_reset" >> /etc/sudoers
#4.3	4.3.7	Ensure access to the su command is restricted
groupadd sugroup
echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su
#4.4		Configure Pluggable Authentication Modules
#4.4.1		Configure PAM software packages
#4.4.1	4.4.1.1	Ensure latest version of pam is installed
dnf upgrade pam -y
#4.4.1	4.4.1.2	Ensure latest version of authselect is installed
dnf install authselect -y
dnf upgrade authselect -y
#4.4.2		Configure authselect
#4.4.2	4.4.2.1	Ensure active authselect profile includes pam modules
authselect create-profile custom-profile -b sssd
authselect select custom/custom-profile --backup=PAM_CONFIG_BACKUP --force
#4.4.2	4.4.2.2	Ensure pam_faillock module is enabled
authselect enable-feature with-faillock
authselect apply-changes
#4.4.2	4.4.2.3	Ensure pam_pwquality module is enabled
authselect enable-feature with-pwquality
authselect apply-changes
#4.4.2	4.4.2.4	Ensure pam_pwhistory module is enabled
authselect enable-feature with-pwhistory
authselect apply-changes
#4.4.2	4.4.2.5	Ensure pam_unix module is enabled
echo "Managed by IDM"
#4.4.3		Configure pluggable module arguments
#4.4.3.1		Configure pam_faillock module
sed -i 's/# deny*.*/deny = 5/' /etc/security/faillock.conf
#4.4.3.1	4.4.3.1.1	Ensure password failed attempts lockout is configured
sed -i 's/# unlock_time*.*/unlock_time = 900/' /etc/security/faillock.conf
#4.4.3.1	4.4.3.1.2	Ensure password unlock time is configured
echo "Managed by IDM"
#4.4.3.2		Configure pam_pwquality module
#4.4.3.2	4.4.3.2.1	Ensure password number of changed characters is configured
sed -ri 's/^\s*difok\s*=/# &/' /etc/security/pwquality.conf 
printf '\n%s' "difok = 2" >> /etc/security/pwquality.conf.d/50-pwdifok.conf
#4.4.3.2	4.4.3.2.2	Ensure password length is configured
sed -i 's/#minlen = 8/minlen = 14/' /etc/security/pwquality.conf
echo "minlen = 14" >> /etc/security/pwquality.conf
#4.4.3.2	4.4.3.2.3	Ensure password complexity is configured
sed -i 's/# minclass = 0/minclass = 4/' /etc/security/pwquality.conf
touch /etc/security/pwquality.conf.d/50-pwcomplexity.conf
echo  "minclass = 4" >> /etc/security/pwquality.conf.d/50-pwcomplexity.conf
sed -ri 's/^\s*[dulo]credit\s*=/# &/' /etc/security/pwquality.conf 
printf  "dcredit = -1" "ucredit = -1" "ocredit = -1" "lcredit = -1" > /etc/security/pwquality.conf.d/50-pwcomplexity.conf
#4.4.3.2	4.4.3.2.4	Ensure password same consecutive characters is configured
sed -ri 's/^\s*maxrepeat\s*=/# &/' /etc/security/pwquality.conf
printf  "maxrepeat = 3" >> /etc/security/pwquality.conf.d/50-pwrepeat.conf
#4.4.3.2	4.4.3.2.5	Ensure password maximum sequential characters is configured
sed -ri 's/^\s*maxsequence\s*=/# &/' /etc/security/pwquality.conf 
printf  "maxsequence = 3" >> /etc/security/pwquality.conf.d/50-pwmaxsequence.conf
#4.4.3.2	4.4.3.2.6	Ensure password dictionary check is enabled
sed -ri 's/^\s*dictcheck\s*=/# &/' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
#4.4.3.2	4.4.3.2.7	Ensure password quality is enforced for the root user
echo "enforce_for_root" >> /etc/security/pwquality.conf
touch /etc/security/pwquality.conf.d/50-pwroot.conf
echo "enforce_for_root" >> /etc/security/pwquality.conf.d/50-pwroot.conf
#4.4.3.3		Configure pam_pwhistory module
#4.4.3.3	4.4.3.3.1	Ensure password history remember is configured
sed -ri 's/# remember.*/remember = 24/' /etc/security/pwhistory.conf
#4.4.3.3	4.4.3.3.2	Ensure password history is enforced for the root user
sed -ri 's/# enforce_for_root/enforce_for_root/' /etc/security/pwhistory.conf
#4.4.3.3	4.4.3.3.3	Ensure pam_pwhistory includes use_authtok
echo "Managed by IDM"
#4.4.3.4		Configure pam_unix module
#4.4.3.4	4.4.3.4.1	Ensure pam_unix does not include nullok
authselect enable-feature without-nullok
authselect apply-changes
#4.4.3.4	4.4.3.4.2	Ensure pam_unix does not include remember
authselect apply-changes
#4.4.3.4	4.4.3.4.3	Ensure pam_unix includes a strong password hashing algorithm
authselect apply-changes
#4.4.3.4	4.4.3.4.4	Ensure pam_unix includes use_authtok
authselect apply-changes
#4.5		User Accounts and Environment
#4.5.1		Configure shadow password suite parameters
#4.5.1	4.5.1.1	Ensure strong password hashing algorithm is configured
sed -ri 's/^\s*crypt_style.*/crypt_style = sha512/' /etc/libuser.conf
sed -ri 's/^\s*ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
#4.5.1	4.5.1.2	Ensure password expiration is 365 days or less
sed -ri 's/^\s*PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
#4.5.1	4.5.1.3	Ensure password expiration warning days is 7 or more
sed -ri 's/^\s*PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
#4.5.1	4.5.1.4	Ensure inactive password lock is 30 days or less
useradd -D -f 30
#4.5.1	4.5.1.5	Ensure all users last password change date is in the past
echo "managed by IDM"
#4.5.2		Configure root and system accounts and environment
#4.5.2	4.5.2.1	Ensure default group for the root account is GID 0
usermod -g 0 root
#4.5.2	4.5.2.2	Ensure root user umask is configured
grep -Psi -- '^\h*umask\h+(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b|[0-7][0-7][0-6]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc
#4.5.2	4.5.2.3	Ensure system accounts are secured
echo "This is not applicacable"
#4.5.2	4.5.2.4	Ensure root password is set
sudo sh -c 'echo root:P@ssw0rd@123 | chpasswd'
#4.5.3		Configure user default environment
#4.5.3	4.5.3.2	Ensure default user shell timeout is configured
touch /etc/profile.d/tmout.sh
echo "readonly TMOUT=900 ; export TMOUT" >> /etc/profile.d/tmout.sh
#4.5.3	4.5.3.3	Ensure default user umask is configured
sed -i 's/UMASK.*/UMASK           027/' /etc/login.defs
sed -i 's/USERGROUPS_ENAB yes/USERGROUPS_ENAB no/' /etc/login.defs
#5		Logging and Auditing
#5.1		Configure Logging
#5.1	5.1.3	Ensure logrotate is configured
echo "logrotate configured with the OS"
#5.1	5.1.4	Ensure all logfiles have appropriate access configured
find /var/log -type f -exec chmod g-wx,o-rwx {} +
find /var/log -type f -exec chmod g-wx,o-rwx '{}' + -o -type d -exec chmod g-w,o-rwx '{}' +
#5.1.1		Configure rsyslog
#5.1.1	5.1.1.1	Ensure rsyslog is installed
dnf install rsyslog -y
#5.1.1	5.1.1.2	Ensure rsyslog service is enabled
systemctl --now enable rsyslog
#5.1.1	5.1.1.3	Ensure journald is configured to send logs to rsyslog
sed -ri 's/^\s*#ForwardToSyslog=no/ForwardToSyslog=yes/' /etc/systemd/journald.conf
#5.1.1	5.1.1.4	Ensure rsyslog default file permissions are configured
echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf
#5.1.1	5.1.1.5	Ensure logging is configured
systemctl restart rsyslog
#5.1.1	5.1.1.6	Ensure rsyslog is configured to send logs to a remote log host
systemctl restart rsyslog
#5.1.1	5.1.1.7	Ensure rsyslog is not configured to receive logs from a remote client
systemctl restart rsyslog
#5.1.2		Configure journald
#5.1.2	5.1.2.2	Ensure journald service is enabled
dnf install systemd-journal-remote -y
systemctl enable systemd-journald.service
#5.1.2	5.1.2.3	Ensure journald is configured to compress large log files
sed -i 's/#Compress=yes/Compress=yes/' /etc/systemd/journald.conf
#5.1.2	5.1.2.4	Ensure journald is configured to write logfiles to persistent disk
sed -i 's/#Storage.*/Storage=persistent/' /etc/systemd/journald.conf
#5.1.2	5.1.2.5	Ensure journald is not configured to send logs to rsyslog
sed -i 's/#ForwardToSyslog.*/ForwardToSyslog=yes/' /etc/systemd/journald.conf
#5.1.2	5.1.2.6	Ensure journald log rotation is configured per site policy
echo "logrotate configured with the OS"
#5.1.2.1		Ensure journald is configured to send logs to a remote log host
#5.1.2.1	5.1.2.1.1	Ensure systemd-journal-remote is installed
dnf install systemd-journal-remote -y
#5.1.2.1	5.1.2.1.2	Ensure systemd-journal-remote is configured
systemctl restart systemd-journal-upload
#5.1.2.1	5.1.2.1.3	Ensure systemd-journal-remote is enabled
systemctl --now enable systemd-journal-upload.service
#5.1.2.1	5.1.2.1.4	Ensure journald is not configured to receive logs from a remote client
systemctl --now mask systemd-journal-remote.socket
#5.2		Configure System Accounting (auditd)
#5.2.1		Ensure auditing is enabled
#5.2.2		Configure Data Retention
#5.2.3		Configure auditd rules
#5.2.4		Configure auditd file access
#5.3		Configure Integrity Checking
#5.3	5.3.1	Ensure AIDE is installed
dnf install aide -y
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
#5.3	5.3.2	Ensure filesystem integrity is regularly checked
systemctl is-enabled aidecheck.service
systemctl is-enabled aidecheck.timer
#5.3	5.3.3	Ensure cryptographic mechanisms are used to protect the integrity of audit tools
crontab -l | { cat; echo "0 5 * * * /usr/sbin/aide --check"; } | crontab -
echo "/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
echo "/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
echo "/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
echo "/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
echo "/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
echo "/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
#6		System Maintenance
#6.1		System File Permissions
#6.1	6.1.1	Ensure permissions on /etc/passwd are configured
chmod u-x,go-wx /etc/passwd
chown root:root /etc/passwd
#6.1	6.1.2	Ensure permissions on /etc/passwd- are configured
chmod u-x,go-wx /etc/passwd- 
chown root:root /etc/passwd-
#6.1	6.1.3	Ensure permissions on /etc/opasswd are configured
[ -e "/etc/security/opasswd" ] && chmod u-x,go-rwx /etc/security/opasswd 
[ -e "/etc/security/opasswd" ] && chown root:root /etc/security/opasswd 
[ -e "/etc/security/opasswd.old" ] && chmod u-x,go-rwx /etc/security/opasswd.old
[ -e "/etc/security/opasswd.old" ] && chown root:root /etc/security/opasswd.old
#6.1	6.1.4	Ensure permissions on /etc/group are configured
chmod u-x,go-wx /etc/group
chown root:root /etc/group
#6.1	6.1.5	Ensure permissions on /etc/group- are configured
chmod u-x,go-wx /etc/group-
chown root:root /etc/group-
#6.1	6.1.6	Ensure permissions on /etc/shadow are configured
chown root:root /etc/shadow
chmod 0000 /etc/shadow
#6.1	6.1.7	Ensure permissions on /etc/shadow- are configured
chown root:root /etc/shadow- 
chmod 0000 /etc/shadow-
#6.1	6.1.8	Ensure permissions on /etc/gshadow are configured
chown root:root /etc/gshadow 
chmod 0000 /etc/gshadow
#6.1	6.1.9	Ensure permissions on /etc/gshadow- are configured
chown root:root /etc/gshadow- 
chmod 0000 /etc/gshadow-
#6.1	6.1.10	Ensure permissions on /etc/shells are configured
chmod u-x,go-wx /etc/shells 
chown root:root /etc/shells
#6.1	6.1.11	Ensure world writable files and directories are secured
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup
find / -xdev -nogroup
chown root:root /var/lib/private/systemd/journal-upload/
mkdir -p /etc/scripts/
touch /etc/scripts/set-journal-upload.sh
chmod +x /etc/scripts/set-journal-upload.sh
echo "chmod 0600 /var/lib/private/systemd/journal-upload/" >> /etc/scripts/set-journal-upload.sh
echo "chown root:root /var/lib/private/systemd/journal-upload" >> /etc/scripts/set-journal-upload.sh
crontab -l | { cat; echo "@reboot /etc/scripts/set-journal-upload.sh"; } | crontab -
#6.1	6.1.12	Ensure no unowned or ungrouped files or directories exist
echo "Already Applied"
#6.1	6.1.13	Ensure SUID and SGID files are reviewed
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000
find / -xdev -type f -perm -4000
#6.2		Local User and Group Settings
##6.2	6.2.1	Ensure accounts in /etc/passwd use shadowed passwords
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
#6.2	6.2.8	Ensure root path integrity
echo "remediated with the patching "
#6.2	6.2.9	Ensure root is the only UID 0 account
echo "remediated with the patching "
#6.2	6.2.10	Ensure local interactive user home directories are configured
echo "remediated with the patching "
#6.2	6.2.11	Ensure local interactive user dot files access is configured
echo "remediated with the patching "
############################END OF SCRIPT########################
echo "The script has completed and kindly run the CIS Assesor to get the CIS Benchmark Score."