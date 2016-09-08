To set up a basic Linux wifi access point you basically just:

1. bring the wireless card interface with an IP address.
2. run a DHCP server on the interface so users who connect can get an IP address.
3. set up a firewall to route users to the internet through existing already connected interface.
4. set up a DNS server on the access point so users can resolve names.
5. set an SSID, advertise, and allow users to connect to the access point.

Everything is done at the command line with,

dhcpcd 
dnsmasq
ip 
lighttpd 
hostapd
iptables

This script is meant for testing but can be modified to suit your needs.

