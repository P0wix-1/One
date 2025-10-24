#!/bin/python3
import os

os.system("mkdir /etc/net/ifaces/ens19")
os.system("mkdir /etc/net/ifaces/ens20")

os.system("echo '192.168.1.1/24' > /etc/net/ifaces/ens19/ipv4address")
os.system("echo '192.168.2.1/24' > /etc/net/ifaces/ens20/ipv4address")
os.system("cat << OEF > /etc/net/ifaces/ens19/options\n BOOTPROTO=static\n TYPE=eth\n CONFIG_WIRELESS=no\n SYSTEMD_BOOTPROTO=static\n CONFIG_IPV4=yes\n DISABLED=no\n NM_CONTROLLED=no\n SYSTEMD_CONTROLLED=no")
os.system("cat << OEF > /etc/net/ifaces/ens20/options\n BOOTPROTO=static\n TYPE=eth\n CONFIG_WIRELESS=no\n SYSTEMD_BOOTPROTO=static\n CONFIG_IPV4=yes\n DISABLED=no\n NM_CONTROLLED=no\n SYSTEMD_CONTROLLED=no")

os.system("hostnamectl set-hostname ISP")
os.system("sudo sysctl -w net.ipv4.ip_forward=1")

os.system("systemctl restart network")

os.system("apt-get update && apt-get -y install firewalld && systemctl enable --now firewalld")
os.system("firewall-cmd --permanent --zone=public --add-interface=ens18")
os.system("firewall-cmd --permanent --zone=trusted --add-interface=ens19")
os.system("firewall-cmd --permanent --zone=trusted --add-interface=ens20")
os.system("firewall-cmd --permanent --zone=public --add-masquerade")
os.system("firewall-cmd --complete-reload")
