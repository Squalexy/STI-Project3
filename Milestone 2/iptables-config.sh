# Disable default firewall
systemctl stop firewalld
systemctl disable firewalld

# Enable packet forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Flush all iptables rules
iptables -F

# Drop all communications
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Optional step: allow SSH connections from local machine
iptables -A INPUT -s 192.168.6.0/24 -j ACCEPT

# Provide connection tracking support for FTP
modprobe nf_conntrack_ftp

# -------------------------------------------------------------- #

# DNS name resolutions requests sent to outside servers
# TCP
iptables -A OUTPUT -p tcp --dport domain -j ACCEPT
iptables -A INPUT -p tcp --dport domain -j ACCEPT

# UDP
iptables -A OUTPUT -p udp --dport domain -j ACCEPT
iptables -A INPUT -p udp --dport domain -j ACCEPT


# SSH connections to the router system, originated at Internal or vpn-gw
# Internal network
iptables -A INPUT -s 192.168.10.0/24 -p tcp --dport ssh -j ACCEPT

# vpn-gw
iptables -A INPUT -s 23.214.219.253 -p tcp --dport ssh -j ACCEPT

# -------------------------------------------------------------- #

# Authorize direct communications without NAT

# Domain name resolutions using the dns server
iptables -A FORWARD -p udp -d 23.214.219.253 --dport domain -j ACCEPT
iptables -A FORWARD -p udp -s 23.214.219.253 --dport domain -j ACCEPT

# The dns server should be able to resolve names using DNS servers on the Internet (dns2 and also others).
iptables -A FORWARD -p tcp -d 23.214.219.253 --dport domain -j ACCEPT
iptables -A FORWARD -p tcp -s 23.214.219.253 --dport domain -j ACCEPT

# SMTP connections to the smtp server
iptables -A FORWARD -p tcp -d 23.214.219.253 --dport smtp -j ACCEPT

# POP and IMAP connections to the mail server
iptables -A FORWARD -p tcp -d 23.214.219.253 --dport pop3 -j ACCEPT
iptables -A FORWARD -p tcp -d 23.214.219.253 --dport imap -j ACCEPT

# HTTP and HTTPS connections to the www server
iptables -A FORWARD -p tcp -d 23.214.219.253 --dport http -j NFQUEUE --queue-num 0
iptables -A FORWARD -p tcp -d 23.214.219.253 --dport https -j NFQUEUE --queue-num 0

# OpenVPN connections to the vpn-gw server
iptables -A FORWARD -p tcp -d 23.214.219.253 --dport openvpn -j ACCEPT

# VPN clients connected to the gateway should be able to connect to all services in the Internal network
iptables -A FORWARD -s 23.214.219.253 -d 192.168.10.0/24 -j ACCEPT
iptables -A FORWARD -s 192.168.10.0/24 -d 23.214.219.253 -j ACCEPT

# -------------------------------------------------------------- #

# Connections to external IP address of firewall using NAT

# FTP connections (passive and active)
iptables -t nat -A PREROUTING -p tcp -d 87.248.214.97 --dport ftp -j DNAT --to-destination 192.168.10.253
iptables -t nat -A PREROUTING -p tcp -d 87.248.214.97 --dport ftp-data -j DNAT --to-destination 192.168.10.253
iptables -A FORWARD -p tcp -d 192.168.10.253 --dport ftp -j ACCEPT
iptables -A FORWARD -p tcp -d 192.168.10.253 --dport ftp-data -j ACCEPT

# SSH connections to datastore server, originated at eden or dns2
iptables -t nat -A PREROUTING -d 87.248.214.97 -s 87.248.214.100 -p tcp --dport ssh -j DNAT --to-destination 192.168.10.253
iptables -A FORWARD -d 192.168.10.253 -s 87.248.214.100 -p tcp --dport ssh -j ACCEPT

# -------------------------------------------------------------- #

# Communications from Internal network to Internet network using NAT

# Domain name resolutions using DNS
iptables -t nat -A POSTROUTING -p udp -s 192.168.10.0/24 --dport domain -j SNAT --to-source 87.248.214.100
iptables -t nat -A POSTROUTING -p tcp -s 192.168.10.0/24 --dport domain -j SNAT --to-source 87.248.214.100
iptables -A FORWARD -p udp -s 192.168.10.0/24 --dport domain -j ACCEPT
iptables -A FORWARD -p tcp -s 192.168.10.0/24 --dport domain -j ACCEPT

# HTTP, HTTPS and SSH connections
# HTTP
iptables -t nat -A POSTROUTING -p tcp -s 192.168.10.0/24 --dport http -j SNAT --to-source 87.248.214.100
iptables -A FORWARD -p tcp -s 192.168.10.0/24 --dport http -j ACCEPT

# HTTPS
iptables -t nat -A POSTROUTING -p tcp -s 192.168.10.0/24 --dport https -j SNAT --to-source 87.248.214.100
iptables -A FORWARD -s 192.168.10.0/24 -p tcp --dport https -j ACCEPT

# SSH
iptables -t nat -A POSTROUTING -p tcp -s 192.168.10.0/24 --dport ssh -j SNAT --to-source 87.248.214.100
iptables -A FORWARD -s 192.168.10.0/24 -p tcp --dport ssh -j ACCEPT

# FTP connections (passive and active) to external FTP servers
iptables -t nat -A POSTROUTING -p tcp -s 192.168.10.0/24 --dport ftp -j SNAT --to-source 87.248.214.100
iptables -t nat -A POSTROUTING -p tcp -s 192.168.10.0/24 --dport ftp-data -j SNAT --to-source 87.248.214.100
iptables -A FORWARD -p tcp -s 192.168.10.0/24 --dport ftp -j ACCEPT
iptables -A FORWARD -p tcp -s 192.168.10.0/24 --dport ftp-data -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# -------------------------------------------------------------- #

iptables -L
