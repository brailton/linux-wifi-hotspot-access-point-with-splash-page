#!/bin/bash

#Barry Railton 2016-09-03.
#Linux Wireless 802.11 Wireless Access Point with Splash Page.
#README, tutorial, and simple script combined. 

#In this repo you will also find:
#   A root directory /srv/www/http for the lighttpd webserver that contains the splash page content. 
#   A config file /etc/lighttpd/lighttpd.conf for the lighttpd webserver.

#Software requirements (these are the key compoents):
#   hostapd https://w1.fi/hostapd/ This sets up the access point.
#   dnsmasq http://www.thekelleys.org.uk/dnsmasq/doc.html This provides DNS and DHCP to the AP network.
#   dhcpcd https://wiki.archlinux.org/index.php/dhcpcd BSD DHCP client to get host IP address.
#   lighttpd https://www.lighttpd.net/ A web server.
#   iptables https://www.netfilter.org/ for firewall rules.

#Hardware requirements:
#   A wireless network card capable of supporting access point mode.
#   A second network card (either wireless or wired) that already has internet access.

#Users and rights:
#   User http along with group of same name must exist.
#   User http must have sudo to update iptables (put "http ALL=(ALL) NOPASSWD: /usr/bin/iptables" in /etc/sudoers file).
#   Sudo is required to run this script.

#Definitions:
#   INTERFACE_AP = the interface used for the wireless accesspoint hotspot.
#   INTERFACE_NON_AP = the interface traffic will be routed through to get the the internet (this can also be wireless).

#Also:
#   Script assumes no inital network connectivity and brings all interfaces down before proceeding.
#   Echo statements and read pauses are there for transparency. Remove whenever.

#BEGIN

#Clean up any old processes. Make sure any start up scripts (init and systemd) are disabled stopped.
#Seriously, these daemons have ways of springing to life unexpectedly and taking your network down.
#Make sure they are jailed and killed before proceeding.
for PROCESS in NetworkManager netctl wpa_supplicant dhclient dhcpcd hostapd dnsmasq lighttpd
	do
	killall -9 2>/dev/null $PROCESS 
	done

#Clean old firewall rules.
iptables -F 
iptables -t nat -F 

#Flush any existing IP addresses.
#Note, the ip command numbers the NICs and local 127.0.0.1 is always number 1.
#So we grep for cards starting with the number 2.
#Anything in inside $(...) is "expanded" by the shell. 
for LINK in $(ip link|egrep ^[2-9]|awk '{print $2}')
	do
	ip address flush dev $LINK
	ip link set $LINK down
	ip link set $LINK up
	done

#Uncomment the wpa_supplicant command below if your non AP interface is also wireless and uses WPA. 
#This is a nice trick for authenticating to a WPA access point at the command line.
#	echo "starting wpa_supplicant..."
#	wpa_supplicant -B -D nl80211,wext -i wlp3s0 -c <(wpa_passphrase "SSID" 'Secret')
#	echo "enter to continue..."; read

#Try to get an IPv4 address from all interfaces.
echo "starting dhcpcd..."
dhcpcd -4 || echo "connot get IP address"
echo "enter to continue..."; read

#Find AP and NON_AP interfaces. Which is which?

#INTERFACE_NON_AP will be the current DHCP lease if there is one. 
#Looking for a better way to do this. But this works.
echo "Running dhcpcd -T to get current INTERFACE_NON_AP"
INTERFACE_NON_AP=$(dhcpcd -T|grep -w leased|cut -d: -f1)

#Get INTERFACE_NON_AP IP address also.
echo "Running dhcpcd -T to get current AP interface IP"
INTERFACE_NON_AP_IP=$(dhcpcd -T|grep -w leased|cut -d" " -f3)

#Check we have an interface and an IP addresss before proceeding.
echo "INTERFACE_NON_AP = $INTERFACE_NON_AP IP = $INTERFACE_NON_AP_IP"
echo "enter to continue..."; read

#Exit if no IP address.
if [[ $INTERFACE_NON_AP_IP == "" ]];then
	echo "$INTERFACE_NON_AP has no IP address, giving up"; exit 
fi

#INTERFACE_AP must be a wireless card that is not also INTERFACE_NON_AP. 
#Use the iw command to get all wireless devices on the current system. 
#Then cycle through to find one that isn't the current $INTERFACE_NON_AP that is already in use.
for INTERFACE in $(iw dev|grep -w Interface|awk '{print $2}')
	do
	if [[ $INTERFACE != $INTERFACE_NON_AP ]];then
	INTERFACE_AP=$INTERFACE 
	fi
	done

#Flush any old IP addreeses and bring up AP interface
ip addr flush dev $INTERFACE_AP
ip link set $INTERFACE_AP up

#Set up some firewall rules to allow forwarding and masquerading between INTERFACES. 
iptables -A FORWARD -i $INTERFACE_AP
iptables -A FORWARD -o $INTERFACE_AP
iptables -t nat -A POSTROUTING -o $INTERFACE_NON_AP -j MASQUERADE
echo 1 >/proc/sys/net/ipv4/ip_forward

#Now assign an IP address to the hotspot AP INTERFACE_AP.
#This must be in a different subnet than INTERFACE_NON_AP. 
#So pick either 192.168.0.1/24 or 10.10.0.1/24, whichever is not being used. 
#Also note, the lease time is set for 30m = 30 minutes.
if [[ $INTERFACE_NON_AP_IP != 192.* ]]; then 
	INTERFACE_AP_IP=192.168.0.1
	RANGE="192.168.0.100,192.168.0.200,255.255.255.0,30m"
else
	INTERFACE_AP_IP=10.10.0.1
	RANGE="10.10.0.100,10.10.0.200,255.255.255.0,30m"
fi

#Check we have an interface for the AP and that it has an IP address to assign.
echo "echo INTERFACE_AP = $INTERFACE_AP, IP = $INTERFACE_AP_IP"
echo "enter to continue...."

#Assign IP address to AP interface.
ip addr add $INTERFACE_AP_IP/24 dev $INTERFACE_AP

#Start dnsmasq. This provides DNS and DHCP. 
#Here we define a --dhcp-script to run when users join and get an IP address. 
#This script adds an iptables entry to forward new IP addresses to the new user splash page on port 80.
#At the splash page users take a survey, watch an advertisement, or acknowledge a public announcement, for example. 
#Upon user succesful form submission the iptables firewall rule created by the --dhcp-script is removed.

echo "starting dnsmasq...."
dnsmasq -i $INTERFACE_AP --dns-loop-detect --dhcp-range=$RANGE --log-queries=extra --log-dhcp --all-servers --dhcp-sequential --dhcp-script=/root/bin/dhcp-script.sh --host-record=home,$INTERFACE_AP_IP

#Now make the dhcp-script with an iptables rule to send new users to $INTERFACE_AP_IP.
#Note, $3 is the IP address dhcpcd has assigned to the user.
#We want '$3' in the script file, hence the \ escape character.
echo '#!/bin/bash' >/root/bin/dhcp-script.sh
echo "iptables -t nat -A PREROUTING -s \$3 -p tcp --dport 80 -j DNAT --to-destination $INTERFACE_AP_IP" >>/root/bin/dhcp-script.sh
echo "iptables -t nat -A PREROUTING -s \$3 -p tcp --dport 443 -j DNAT --to-destination $INTERFACE_AP_IP:80" >>/root/bin/dhcp-script.sh
chmod 500 /root/bin/dhcp-script.sh
#This will create an entry like
#iptables -t nat -A PREROUTING -s $3 -p tcp --dport 80 -j DNAT --to-destination 192.168.0.1:80
#in /root/bin/dhcp-script.sh so new users always get redirected to the splash page.
#$3 will be replaced by the IP address that dhcpcd assigns.

#And while we are making scripts, let's also create a CGI script the webserver can call to remove the iptables rule after the user interacts with the splash page.
echo '#!/bin/bash' >/srv/http/allow_guest.cgi
echo "echo \"Hey be cool you who has $REMOTE_ADDR IP address\"">>/srv/http/allow_guest.cgi
echo "sudo /sbin/iptables -t nat -D PREROUTING -s \$HTTP_ADDR -p tcp --dport 80 -j DNAT --to-destination $INTERFACE_AP_IP" >>/srv/http/allow_guest.cgi
chmod 500 /srv/http/allow_guest.cgi
chown html:html /srv/http/allow_guest.cgi

#This will create an entry like this 
#iptables -t nat -D PREROUTING -s $REMOTE_ADDR  -p tcp --dport 80 -j DNAT --to-destination 192.168.0.1:80
#in /srv/http/allow_guest.cgi which gets called from the users web browser and deletes redirect rule thus allowing access.
#Here $REMOTE_ADDR is the environment variable that contains the user's IP address.

#Now update the lighttpd conf file to bind to the correct AP hotspot interface.
#If the string "server.bind" exists, replace it with the correct value.
#Otherwise `||' (if it does not exist) append it to the conf file. 
grep -q "server.bind" /etc/lighttpd/lighttpd.conf && sed -i "s/.*server.bind.*/server.bind=\"${INTERFACE_AP_IP}\"/" /etc/lighttpd/lighttpd.conf || echo "server.bind=$\"{INTERFACE_AP_IP}\"" >> /etc/lighttpd/lighttpd.conf
lighttpd -f /etc/lighttpd/lighttpd.conf

#Make a hostapd.conf file for a Raspberry PI.
#This section to be replaced with wget with multiple URL options for multiple devices. 
#Also of interest is auto writing a conf file based on a probe of the card.
#If you are not familiar with the following <<EOF syhtax, this is known as a Here Document: https://en.wikipedia.org/wiki/Here_document
cat << EOF > /tmp/hostapd.conf
ssid=:30_FREE_LOVE!
interface=$INTERFACE_AP
channel=7
hw_mode=g
ieee80211n=1
logger_stdout=1
logger_stdout_level=2
max_num_sta=5
EOF

#Now start hostapd. This is the basic daemon that sets up wifi access. 
#The config file created in the provious step can be modified to allow for WPA authentication if reuired.
echo "starting hostapd...."
hostapd -B /tmp/hostapd.conf

#END

