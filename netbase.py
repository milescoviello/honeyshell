"""The files the `netbase` package owns, verbatim from the guest.

Why this exists: /etc/services held three lines. A real Debian 13 has 365,
and every one of them is a fact some tool on the box will be asked for --
`getent services mysql`, `grep 3306 /etc/services`, `ss -tl` resolving
a port to a name. /etc/protocols had four lines against 68, /etc/rpc and
/etc/ethertypes were missing outright, and `dpkg -l netbase` said the
package that owns all four was not installed while three of them sat on
the disk. Three answers to "does this box have a service database": the
filesystem said yes, dpkg said no package put them there, and getent --
whose only job is to read them -- said nothing at all.

Stock package data, copied from the guest rather than retyped, so
`grep`, `getent` and `wc -l` agree with a real trixie by construction.
"""

SERVICES = r'''# Network services, Internet style
#
# Updated from https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml .
#
# New ports will be added on request if they have been officially assigned
# by IANA and used in the real-world or are needed by a debian package.
# If you need a huge list of used numbers please install the nmap package.

tcpmux		1/tcp				# TCP port service multiplexer
echo		7/tcp
echo		7/udp
discard		9/tcp		sink null
discard		9/udp		sink null
systat		11/tcp		users
daytime		13/tcp
daytime		13/udp
netstat		15/tcp
qotd		17/tcp		quote
chargen		19/tcp		ttytst source
chargen		19/udp		ttytst source
ftp-data	20/tcp
ftp		21/tcp
fsp		21/udp		fspd
ssh		22/tcp				# SSH Remote Login Protocol
telnet		23/tcp
smtp		25/tcp		mail
time		37/tcp		timserver
time		37/udp		timserver
whois		43/tcp		nicname
tacacs		49/tcp				# Login Host Protocol (TACACS)
tacacs		49/udp
domain		53/tcp				# Domain Name Server
domain		53/udp
bootps		67/udp
bootpc		68/udp
tftp		69/udp
gopher		70/tcp				# Internet Gopher
finger		79/tcp
http		80/tcp		www		# WorldWideWeb HTTP
kerberos	88/tcp		kerberos5 krb5 kerberos-sec	# Kerberos v5
kerberos	88/udp		kerberos5 krb5 kerberos-sec	# Kerberos v5
iso-tsap	102/tcp		tsap		# part of ISODE
acr-nema	104/tcp		dicom		# Digital Imag. & Comm. 300
pop3		110/tcp		pop-3		# POP version 3
sunrpc		111/tcp		portmapper	# RPC 4.0 portmapper
sunrpc		111/udp		portmapper
auth		113/tcp		authentication tap ident
nntp		119/tcp		readnews untp	# USENET News Transfer Protocol
ntp		123/udp				# Network Time Protocol
epmap		135/tcp		loc-srv		# DCE endpoint resolution
netbios-ns	137/udp				# NETBIOS Name Service
netbios-dgm	138/udp				# NETBIOS Datagram Service
netbios-ssn	139/tcp				# NETBIOS session service
imap2		143/tcp		imap		# Interim Mail Access P 2 and 4
snmp		161/tcp				# Simple Net Mgmt Protocol
snmp		161/udp
snmp-trap	162/tcp		snmptrap	# Traps for SNMP
snmp-trap	162/udp		snmptrap
cmip-man	163/tcp				# ISO mgmt over IP (CMOT)
cmip-man	163/udp
cmip-agent	164/tcp
cmip-agent	164/udp
mailq		174/tcp			# Mailer transport queue for Zmailer
xdmcp		177/udp			# X Display Manager Control Protocol
bgp		179/tcp				# Border Gateway Protocol
smux		199/tcp				# SNMP Unix Multiplexer
qmtp		209/tcp				# Quick Mail Transfer Protocol
z3950		210/tcp		wais		# NISO Z39.50 database
ipx		213/udp				# IPX [RFC1234]
ptp-event	319/udp
ptp-general	320/udp
pawserv		345/tcp				# Perf Analysis Workbench
zserv		346/tcp				# Zebra server
rpc2portmap	369/tcp
rpc2portmap	369/udp				# Coda portmapper
codaauth2	370/tcp
codaauth2	370/udp				# Coda authentication server
clearcase	371/udp		Clearcase
ldap		389/tcp			# Lightweight Directory Access Protocol
ldap		389/udp
svrloc		427/tcp				# Server Location
svrloc		427/udp
https		443/tcp				# http protocol over TLS/SSL
https		443/udp				# HTTP/3
snpp		444/tcp				# Simple Network Paging Protocol
microsoft-ds	445/tcp				# Microsoft Naked CIFS
kpasswd		464/tcp
kpasswd		464/udp
submissions	465/tcp		ssmtp smtps urd # Submission over TLS [RFC8314]
saft		487/tcp			# Simple Asynchronous File Transfer
isakmp		500/udp				# IPSEC key management
rtsp		554/tcp			# Real Time Stream Control Protocol
rtsp		554/udp
nqs		607/tcp				# Network Queuing system
asf-rmcp	623/udp		# ASF Remote Management and Control Protocol
qmqp		628/tcp
ipp		631/tcp				# Internet Printing Protocol
ldp		646/tcp				# Label Distribution Protocol
ldp		646/udp
#
# UNIX specific services
#
exec		512/tcp
biff		512/udp		comsat
login		513/tcp
who		513/udp		whod
shell		514/tcp		cmd syslog	# no passwords used
syslog		514/udp
printer		515/tcp		spooler		# line printer spooler
talk		517/udp
ntalk		518/udp
route		520/udp		router routed	# RIP
gdomap		538/tcp				# GNUstep distributed objects
gdomap		538/udp
uucp		540/tcp		uucpd		# uucp daemon
klogin		543/tcp				# Kerberized `rlogin' (v5)
kshell		544/tcp		krcmd		# Kerberized `rsh' (v5)
dhcpv6-client	546/udp
dhcpv6-server	547/udp
afpovertcp	548/tcp				# AFP over TCP
nntps		563/tcp		snntp		# NNTP over SSL
submission	587/tcp				# Submission [RFC4409]
ldaps		636/tcp				# LDAP over SSL
ldaps		636/udp
tinc		655/tcp				# tinc control port
tinc		655/udp
silc		706/tcp
kerberos-adm	749/tcp				# Kerberos `kadmin' (v5)
#
domain-s	853/tcp				# DNS over TLS [RFC7858]
domain-s	853/udp				# DNS over DTLS [RFC8094]
rsync		873/tcp
ftps-data	989/tcp				# FTP over SSL (data)
ftps		990/tcp
telnets		992/tcp				# Telnet over SSL
imaps		993/tcp				# IMAP over SSL
pop3s		995/tcp				# POP-3 over SSL
#
# From ``Assigned Numbers'':
#
#> The Registered Ports are not controlled by the IANA and on most systems
#> can be used by ordinary user processes or programs executed by ordinary
#> users.
#
#> Ports are used in the TCP [45,106] to name the ends of logical
#> connections which carry long term conversations.  For the purpose of
#> providing services to unknown callers, a service contact port is
#> defined.  This list specifies the port used by the server process as its
#> contact port.  While the IANA can not control uses of these ports it
#> does register or list uses of these ports as a convienence to the
#> community.
#
socks		1080/tcp			# socks proxy server
proofd		1093/tcp
rootd		1094/tcp
openvpn		1194/tcp
openvpn		1194/udp
rmiregistry	1099/tcp			# Java RMI Registry
lotusnote	1352/tcp	lotusnotes	# Lotus Note
ms-sql-s	1433/tcp			# Microsoft SQL Server
ms-sql-m	1434/udp			# Microsoft SQL Monitor
ingreslock	1524/tcp
datametrics	1645/tcp	old-radius
datametrics	1645/udp	old-radius
sa-msg-port	1646/tcp	old-radacct
sa-msg-port	1646/udp	old-radacct
kermit		1649/tcp
groupwise	1677/tcp
l2f		1701/udp	l2tp
radius		1812/tcp
radius		1812/udp
radius-acct	1813/tcp	radacct		# Radius Accounting
radius-acct	1813/udp	radacct
cisco-sccp	2000/tcp			# Cisco SCCP
nfs		2049/tcp			# Network File System
nfs		2049/udp			# Network File System
gnunet		2086/tcp
gnunet		2086/udp
rtcm-sc104	2101/tcp			# RTCM SC-104 IANA 1/29/99
rtcm-sc104	2101/udp
gsigatekeeper	2119/tcp
gris		2135/tcp		# Grid Resource Information Server
cvspserver	2401/tcp			# CVS client/server operations
venus		2430/tcp			# codacon port
venus		2430/udp			# Venus callback/wbc interface
venus-se	2431/tcp			# tcp side effects
venus-se	2431/udp			# udp sftp side effect
codasrv		2432/tcp			# not used
codasrv		2432/udp			# server port
codasrv-se	2433/tcp			# tcp side effects
codasrv-se	2433/udp			# udp sftp side effect
mon		2583/tcp			# MON traps
mon		2583/udp
dict		2628/tcp			# Dictionary server
f5-globalsite	2792/tcp
gsiftp		2811/tcp
gpsd		2947/tcp
gds-db		3050/tcp	gds_db		# InterBase server
icpv2		3130/udp	icp		# Internet Cache Protocol
isns		3205/tcp			# iSNS Server Port
isns		3205/udp			# iSNS Server Port
iscsi-target	3260/tcp
mysql		3306/tcp
ms-wbt-server	3389/tcp
nut		3493/tcp			# Network UPS Tools
nut		3493/udp
distcc		3632/tcp			# distributed compiler
daap		3689/tcp			# Digital Audio Access Protocol
svn		3690/tcp	subversion	# Subversion protocol
suucp		4031/tcp			# UUCP over SSL
sysrqd		4094/tcp			# sysrq daemon
sieve		4190/tcp			# ManageSieve Protocol
epmd		4369/tcp			# Erlang Port Mapper Daemon
remctl		4373/tcp		# Remote Authenticated Command Service
f5-iquery	4353/tcp			# F5 iQuery
ntske		4460/tcp	# Network Time Security Key Establishment
ipsec-nat-t	4500/udp			# IPsec NAT-Traversal [RFC3947]
iax		4569/udp			# Inter-Asterisk eXchange
mtn		4691/tcp			# monotone Netsync Protocol
radmin-port	4899/tcp			# RAdmin Port
sip		5060/tcp			# Session Initiation Protocol
sip		5060/udp
sip-tls		5061/tcp
sip-tls		5061/udp
xmpp-client	5222/tcp	jabber-client	# Jabber Client Connection
xmpp-server	5269/tcp	jabber-server	# Jabber Server Connection
cfengine	5308/tcp
mdns		5353/udp			# Multicast DNS
postgresql	5432/tcp	postgres	# PostgreSQL Database
freeciv		5556/tcp	rptp		# Freeciv gameplay
amqps		5671/tcp			# AMQP protocol over TLS/SSL
amqp		5672/tcp
amqp		5672/sctp
coap		5683/tcp		# Constrained Application Protocol
coap		5683/udp		# Constrained Application Protocol
coaps		5684/tcp			# TLS-secured CoAP
coaps		5684/udp			# DTLS-secured CoAP
x11		6000/tcp	x11-0		# X Window System
x11-1		6001/tcp
x11-2		6002/tcp
x11-3		6003/tcp
x11-4		6004/tcp
x11-5		6005/tcp
x11-6		6006/tcp
x11-7		6007/tcp
gnutella-svc	6346/tcp			# gnutella
gnutella-svc	6346/udp
gnutella-rtr	6347/tcp			# gnutella
gnutella-rtr	6347/udp
redis		6379/tcp
sge-qmaster	6444/tcp	sge_qmaster	# Grid Engine Qmaster Service
sge-execd	6445/tcp	sge_execd	# Grid Engine Execution Service
mysql-proxy	6446/tcp			# MySQL Proxy
babel		6696/udp			# Babel Routing Protocol
ircs-u		6697/tcp		# Internet Relay Chat via TLS/SSL
bbs		7000/tcp
afs3-fileserver 7000/udp
afs3-callback	7001/udp			# callbacks to cache managers
afs3-prserver	7002/udp			# users & groups database
afs3-vlserver	7003/udp			# volume location database
afs3-kaserver	7004/udp			# AFS/Kerberos authentication
afs3-volser	7005/udp			# volume managment server
afs3-bos	7007/udp			# basic overseer process
afs3-update	7008/udp			# server-to-server updater
afs3-rmtsys	7009/udp			# remote cache manager service
font-service	7100/tcp	xfs		# X Font Service
http-alt	8080/tcp	webcache	# WWW caching service
puppet		8140/tcp			# The Puppet master service
bacula-dir	9101/tcp			# Bacula Director
bacula-fd	9102/tcp			# Bacula File Daemon
bacula-sd	9103/tcp			# Bacula Storage Daemon
xmms2		9667/tcp	# Cross-platform Music Multiplexing System
nbd		10809/tcp			# Linux Network Block Device
zabbix-agent	10050/tcp			# Zabbix Agent
zabbix-trapper	10051/tcp			# Zabbix Trapper
amanda		10080/tcp			# amanda backup services
dicom		11112/tcp
hkp		11371/tcp			# OpenPGP HTTP Keyserver
db-lsp		17500/tcp			# Dropbox LanSync Protocol
dcap		22125/tcp			# dCache Access Protocol
gsidcap		22128/tcp			# GSI dCache Access Protocol
wnn6		22273/tcp			# wnn6

#
# Datagram Delivery Protocol services
#
rtmp		1/ddp			# Routing Table Maintenance Protocol
nbp		2/ddp			# Name Binding Protocol
echo		4/ddp			# AppleTalk Echo Protocol
zip		6/ddp			# Zone Information Protocol

#=========================================================================
# The remaining port numbers are not as allocated by IANA.
#=========================================================================

# Kerberos (Project Athena/MIT) services
kerberos4	750/udp		kerberos-iv kdc	# Kerberos (server)
kerberos4	750/tcp		kerberos-iv kdc
kerberos-master	751/udp		kerberos_master	# Kerberos authentication
kerberos-master	751/tcp
passwd-server	752/udp		passwd_server	# Kerberos passwd server
krb-prop	754/tcp		krb_prop krb5_prop hprop # Kerberos slave propagation
zephyr-srv	2102/udp			# Zephyr server
zephyr-clt	2103/udp			# Zephyr serv-hm connection
zephyr-hm	2104/udp			# Zephyr hostmanager
iprop		2121/tcp			# incremental propagation
supfilesrv	871/tcp			# Software Upgrade Protocol server
supfiledbg	1127/tcp		# Software Upgrade Protocol debugging

#
# Services added for the Debian GNU/Linux distribution
#
poppassd	106/tcp				# Eudora
moira-db	775/tcp		moira_db	# Moira database
moira-update	777/tcp		moira_update	# Moira update protocol
moira-ureg	779/udp		moira_ureg	# Moira user registration
spamd		783/tcp				# spamassassin daemon
skkserv		1178/tcp			# skk jisho server port
predict		1210/udp			# predict -- satellite tracking
rmtcfg		1236/tcp			# Gracilis Packeten remote config server
xtel		1313/tcp			# french minitel
xtelw		1314/tcp			# french minitel
zebrasrv	2600/tcp			# zebra service
zebra		2601/tcp			# zebra vty
ripd		2602/tcp			# ripd vty (zebra)
ripngd		2603/tcp			# ripngd vty (zebra)
ospfd		2604/tcp			# ospfd vty (zebra)
bgpd		2605/tcp			# bgpd vty (zebra)
ospf6d		2606/tcp			# ospf6d vty (zebra)
ospfapi		2607/tcp			# OSPF-API
isisd		2608/tcp			# ISISd vty (zebra)
fax		4557/tcp			# FAX transmission service (old)
hylafax		4559/tcp			# HylaFAX client-server protocol (new)
munin		4949/tcp	lrrd		# Munin
rplay		5555/udp			# RPlay audio service
nrpe		5666/tcp			# Nagios Remote Plugin Executor
nsca		5667/tcp			# Nagios Agent - NSCA
canna		5680/tcp			# cannaserver
syslog-tls	6514/tcp			# Syslog over TLS [RFC5425]
sane-port	6566/tcp	sane saned	# SANE network scanner daemon
ircd		6667/tcp			# Internet Relay Chat
zope-ftp	8021/tcp			# zope management by ftp
tproxy		8081/tcp			# Transparent Proxy
omniorb		8088/tcp			# OmniORB
clc-build-daemon 8990/tcp			# Common lisp build daemon
xinetd		9098/tcp
git		9418/tcp			# Git Version Control System
zope		9673/tcp			# zope server
webmin		10000/tcp
kamanda		10081/tcp			# amanda backup services (Kerberos)
amandaidx	10082/tcp			# amanda backup services
amidxtape	10083/tcp			# amanda backup services
sgi-cmsd	17001/udp		# Cluster membership services daemon
sgi-crsd	17002/udp
sgi-gcd		17003/udp			# SGI Group membership daemon
sgi-cad		17004/tcp			# Cluster Admin daemon
binkp		24554/tcp			# binkp fidonet protocol
asp		27374/tcp			# Address Search Protocol
asp		27374/udp
csync2		30865/tcp			# cluster synchronization tool
dircproxy	57000/tcp			# Detachable IRC Proxy
tfido		60177/tcp			# fidonet EMSI over telnet
fido		60179/tcp			# fidonet EMSI over TCP

# Local services
'''

PROTOCOLS = r'''# Internet (IP) protocols
#
# Updated from http://www.iana.org/assignments/protocol-numbers and other
# sources.
# New protocols will be added on request if they have been officially
# assigned by IANA and are not historical.
# If you need a huge list of used numbers please install the nmap package.

ip	0	IP		# internet protocol, pseudo protocol number
hopopt	0	HOPOPT		# IPv6 Hop-by-Hop Option [RFC1883]
icmp	1	ICMP		# internet control message protocol
igmp	2	IGMP		# Internet Group Management
ggp	3	GGP		# gateway-gateway protocol
ipencap	4	IP-ENCAP	# IP encapsulated in IP (officially ``IP'')
st	5	ST		# ST datagram mode
tcp	6	TCP		# transmission control protocol
egp	8	EGP		# exterior gateway protocol
igp	9	IGP		# any private interior gateway (Cisco)
pup	12	PUP		# PARC universal packet protocol
udp	17	UDP		# user datagram protocol
hmp	20	HMP		# host monitoring protocol
xns-idp	22	XNS-IDP		# Xerox NS IDP
rdp	27	RDP		# "reliable datagram" protocol
iso-tp4	29	ISO-TP4		# ISO Transport Protocol class 4 [RFC905]
dccp	33	DCCP		# Datagram Congestion Control Prot. [RFC4340]
xtp	36	XTP		# Xpress Transfer Protocol
ddp	37	DDP		# Datagram Delivery Protocol
idpr-cmtp 38	IDPR-CMTP	# IDPR Control Message Transport
ipv6	41	IPv6		# Internet Protocol, version 6
ipv6-route 43	IPv6-Route	# Routing Header for IPv6
ipv6-frag 44	IPv6-Frag	# Fragment Header for IPv6
idrp	45	IDRP		# Inter-Domain Routing Protocol
rsvp	46	RSVP		# Reservation Protocol
gre	47	GRE		# General Routing Encapsulation
esp	50	IPSEC-ESP	# Encap Security Payload [RFC2406]
ah	51	IPSEC-AH	# Authentication Header [RFC2402]
skip	57	SKIP		# SKIP
ipv6-icmp 58	IPv6-ICMP	# ICMP for IPv6
ipv6-nonxt 59	IPv6-NoNxt	# No Next Header for IPv6
ipv6-opts 60	IPv6-Opts	# Destination Options for IPv6
rspf	73	RSPF CPHB	# Radio Shortest Path First (officially CPHB)
vmtp	81	VMTP		# Versatile Message Transport
eigrp	88	EIGRP		# Enhanced Interior Routing Protocol (Cisco)
ospf	89	OSPFIGP		# Open Shortest Path First IGP
ax.25	93	AX.25		# AX.25 frames
ipip	94	IPIP		# IP-within-IP Encapsulation Protocol
etherip	97	ETHERIP		# Ethernet-within-IP Encapsulation [RFC3378]
encap	98	ENCAP		# Yet Another IP encapsulation [RFC1241]
#	99			# any private encryption scheme
pim	103	PIM		# Protocol Independent Multicast
ipcomp	108	IPCOMP		# IP Payload Compression Protocol
vrrp	112	VRRP		# Virtual Router Redundancy Protocol [RFC5798]
l2tp	115	L2TP		# Layer Two Tunneling Protocol [RFC2661]
isis	124	ISIS		# IS-IS over IPv4
sctp	132	SCTP		# Stream Control Transmission Protocol
fc	133	FC		# Fibre Channel
mobility-header 135 Mobility-Header # Mobility Support for IPv6 [RFC3775]
udplite	136	UDPLite		# UDP-Lite [RFC3828]
mpls-in-ip 137	MPLS-in-IP	# MPLS-in-IP [RFC4023]
manet	138			# MANET Protocols [RFC5498]
hip	139	HIP		# Host Identity Protocol
shim6	140	Shim6		# Shim6 Protocol [RFC5533]
wesp	141	WESP		# Wrapped Encapsulating Security Payload
rohc	142	ROHC		# Robust Header Compression
ethernet 143	Ethernet	# Ethernet encapsulation for SRv6 [RFC8986]
# The following entries have not been assigned by IANA but are used
# internally by the Linux kernel.
mptcp	262	MPTCP		# Multipath TCP connection
'''

RPC = r'''# This file contains user readable names that can be used in place of rpc
# program numbers.

portmapper	100000	portmap sunrpc rpcbind
rstatd		100001	rstat rstat_svc rup perfmeter
rusersd		100002	rusers
nfs		100003	nfsprog
ypserv		100004	ypprog
mountd		100005	mount showmount
ypbind		100007
walld		100008	rwall shutdown
yppasswdd	100009	yppasswd
etherstatd	100010	etherstat
rquotad		100011	rquotaprog quota rquota
sprayd		100012	spray
3270_mapper	100013
rje_mapper	100014
selection_svc	100015	selnsvc
database_svc	100016
rexd		100017	rex
alis		100018
sched		100019
llockmgr	100020
nlockmgr	100021
x25.inr		100022
statmon		100023
status		100024
bootparam	100026
ypupdated	100028	ypupdate
keyserv		100029	keyserver
tfsd		100037 
nsed		100038
nsemntd		100039
ypxfrd		100069
nfs_acl		100227
pcnfsd		150001
amd		300019	amq
sgi_fam		391002
ugidd		545580417
fypxfrd		600100069	freebsd-ypxfrd
bwnfsd          788585389
'''

NETWORKS = r'''default		0.0.0.0
loopback	127.0.0.0
link-local	169.254.0.0

'''

ETHERTYPES = r'''# Ethernet frame types
#
# The EtherType is a two-octet field of Ethernet frames used to indicate
# which protocol is contained in their payload.
#
# More entries, mostly historical, can be found on:
#	https://www.iana.org/assignments/ieee-802-numbers/
#	http://standards-oui.ieee.org/ethertype/eth.txt
#
# <name>	<hexnumber> <alias1>...<alias35> # Comment
#
IPv4		0800	ip ip4	# IP (IPv4)
X25		0805
ARP		0806	ether-arp # Address Resolution Protocol
FR_ARP		0808		# Frame Relay ARP [RFC1701]
BPQ		08FF		# G8BPQ AX.25 over Ethernet
TRILL		22F3		# TRILL [RFC6325]
L2-IS-IS	22F4		# TRILL IS-IS [RFC6325]
TEB		6558		# Transparent Ethernet Bridging [RFC1701]
RAW_FR		6559		# Raw Frame Relay [RFC1701]
RARP		8035		# Reverse ARP [RFC903]
ATALK		809B		# Appletalk
AARP		80F3		# Appletalk Address Resolution Protocol
802_1Q		8100	8021q 1q 802.1q	dot1q # VLAN tagged frame [802.1q]
IPX		8137		# Novell IPX
NetBEUI		8191		# NetBEUI
IPv6		86DD	ip6	# IP version 6
SLOW		8809		# Slow Protocols (LACP, OAM...) [802.3ad]
PPP		880B		# Point-to-Point Protocol
MPLS		8847		# MPLS [RFC5332]
MPLS_MULTI	8848		# MPLS with upstream-assigned label [RFC5332]
ATMMPOA		884C		# MultiProtocol over ATM
PPP_DISC	8863		# PPP over Ethernet discovery stage
PPP_SES		8864		# PPP over Ethernet session stage
ATMFATE		8884		# Frame-based ATM Transport over Ethernet
EAPOL		888E		# EAP over LAN [802.1x]
EtherCAT	88A4		# [IEC 61158]
S-TAG		88A8		# QinQ Service VLAN tag identifier [802.1q]
EAP_PREAUTH	88C7		# EAPOL Pre-Authentication [802.11i]
LLDP		88CC		# Link Layer Discovery Protocol [802.1ab]
MACSEC		88E5		# Media Access Control Security [802.1ae]
PBB		88E7	macinmac # Provider Backbone Bridging [802.1ah]
MVRP		88F5		# Multiple VLAN Registration Protocol [802.1q]
PTP		88F7		# Precision Time Protocol
FCOE		8906		# Fibre Channel over Ethernet
FIP		8914		# FCoE Initialization Protocol
ROCE		8915		# RDMA over Converged Ethernet
LoWPAN		A0ED		# LoWPAN encapsulation
'''

FILES = {
    "/etc/services": SERVICES,
    "/etc/protocols": PROTOCOLS,
    "/etc/rpc": RPC,
    "/etc/networks": NETWORKS,
    "/etc/ethertypes": ETHERTYPES,
}
