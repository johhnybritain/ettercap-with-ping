ettercap-with-ping
==================

Ettercap with added ping and geolocation lookup for active connections. Uses free GeoLite2-City database from maxminddb (http://dev.maxmind.com/geoip/geoip2/geolite2/).

Developed to intercept traffic for online gaming from consoles like xbox 360, and ping peer connected divices to determine network latency that could affect lag in onling games.

Added command line options:

-g --geoip2 <file>   to specify location of GeoLite2-City.mmdb file, default is NULL (if GEOIP enabled)

-x --ping <count>    to specify the number of ping packets to send, default is 5

-X --interval <usec> to specify the ping timeout in microseconds, default is 500000 (0.5 seconds)

-Z --port <port>     to specify the port to use for traceroute

-y --traceroute <cmd> to specify the command to execute to run traceroute, using %d in place of port and %s in place of target host


Added text UI commands:

(xX) lists active connections, pings any remote hosts, and finds geolocation info using the geolite2 database

(aA) lists active connections and finds geolocation info using the geolite2 database


Dependencies:

Needs MaxMind C API (if MaxMind enabled, now obsolete with the addition of whois) (http://dev.maxmind.com/geoip/geoip2/downloadable/)

Needs MaxMind GeoLite2-City.mmdb database (if MaxMind enabled, now obsolete with the addition of whois) (http://dev.maxmind.com/geoip/geoip2/geolite2/)

Example Usage:

Using ettercap ARP poisoning to intercept all xbox live traffic.

ettercap -Tq -f "(ether src 30:59:b7:48:cf:3b) or 
(ether src e4:f4:c6:8b:5a:9c)" -w ettercap.pcap -i eth0 
-M arp:remote /192.168.1.100/ /192.168.1.1/ -P autoadd -Z 3389 -y "lft -d %d %s"

XBOX IP: 192.168.1.100
XBOX MAC: 30:59:b7:48:cf:3b
Internet Router IP: 192.168.1.1
Internet Router MAC: e4:f4:c6:8b:5a:9c

Specify MAC address filters to avoid duplicate packets being captured for both ingress and egress.

The output is in the following format:
Source IP:Port - Destination IP:Port Protocol Status, Transmitted Bytes, Received Bytes, Ping response, WHOIS AS-Org-Name, Org-Name, City, Country

e.g.

Active connection list:

     192.168.1.19:3076  -  137.135.178.35:31003 U active  TX: 966147 RX: 0 PING DST No Reply, Microsoft Corporation, Microsoft Corp, REDMOND, UNITED STATES
     192.168.1.19:3076  -  86.142.192.123:3076  U active  TX: 7184 RX: 1707 PING DST No Reply, BT Public Internet Service, BT-CENTRAL-PLUS IP pools, SHEFFIELD, UNITED KINGDOM
     192.168.1.19:3076  -   82.243.27.158:3076  U active  TX: 7196 RX: 5451 PING DST min/avg/max: 57.4/69.9/92.3 ms loss: 0%, Free SAS, Proxad / Free SAS, CENAC, FRANCE
     192.168.1.19:3076  -    134.3.233.65:3076  U active  TX: 24655 RX: 446 PING DST min/avg/max: 35.5/40.1/50.5 ms loss: 0%, Kabel BW GmbH, Kabel Baden-Wuerttemberg GmbH & Co. KG, STUTTGART, GERMAN
     192.168.1.19:3076  -     2.25.152.44:3076  U active  TX: 7486 RX: 4146 PING DST No Reply, Orange Personal Communications Services, Orange WBC Broadband, LONDON, UNITED KINGDOM
     192.168.1.19:3076  -    46.127.66.92:3776  U active  TX: 7492 RX: 7612 PING DST No Reply, Liberty Global Operations B.V., Cablecom GmbH, CHUR, SWITZERLAND
     192.168.1.19:3076  -    94.7.242.115:3076  U active  TX: 7378 RX: 9269 PING DST min/avg/max: 25.0/29.4/35.7 ms loss: 0%, British Sky Broadcasting Limited, Sky Broadband, LONDON, UNITED KINGDOM
     192.168.1.19:3076  -   86.71.206.214:3076  U active  TX: 7498 RX: 4194 PING DST min/avg/max: 65.7/81.4/106.1 ms loss: 0%, Societe Francaise du Radiotelephone S.A, N9UF-DYN-DSL Dynamic pools, PA
     192.168.1.19:3076  -   91.182.191.76:55053 U active  TX: 5244 RX: 7167 PING DST No Reply, BELGACOM S.A., ADSL-GO-PLUS, BRUSSELS, BELGIUM
     2.126.92.144:3076  -    192.168.1.19:3076  U active  TX: 3846 RX: 4723 PING SRC min/avg/max: 52.7/56.0/59.7 ms loss: 0%, British Sky Broadcasting Limited, Sky Broadband, LONDON, UNITED KINGDOM
     192.168.1.19:3076  -    167.12.36.23:3076  U active  TX: 798 RX: 0 PING DST No Reply, ?, ?, ?, ?
      31.39.57.25:3076  -    192.168.1.19:3076  U active  TX: 3734 RX: 4967 PING SRC No Reply, Bouygues Telecom S.A., BOUYGTEL-ISP-WIRELINE Pool for Broadband DSL Cable customers, VERSAILLES, FRANCE
     192.168.1.19:3076  -   77.102.192.18:3076  U active  TX: 1484 RX: 880 PING DST No Reply, NTL, KNOWSLEY, AIGBURTH, UNITED KINGDOM
     192.168.1.19:51626 - 134.170.178.144:443   T active  TX: 2938 RX: 325 PING DST min/avg/max: 163.0/164.1/165.9 ms loss: 0%, Microsoft Corporation, Microsoft Corp, REDMOND, UNITED STATES
     
exec: lft -d 3389 23.101.173.174
Tracing ....****.*......*****.********.T
TTL LFT trace to 137.135.178.35:3389/tcp
 1  192.168.1.1 0.9ms
 2  10.240.96.1 8.3ms
 3  bmly-core-2b-xe-030-0.network.virginmedia.net (213.105.193.113) 10.1ms
**  [neglected] no reply packets received from TTLs 4 through 6
 7  tcl5-ic-2-ae0-0.network.virginmedia.net (212.250.15.210) 19.8ms
 8  m322-mp2.cvx3-a.ltn.dial.ntli.net (213.104.85.66) 19.5ms
 9  ae7-0.lon04-96cbe-1b.ntwk.msn.net (191.234.81.158) 22.6ms
10  ae4-0.nyc-96cbe-1a.ntwk.msn.net (204.152.141.191) 88.8ms
11  191.234.84.140 97.8ms
12  191.234.81.224 96.1ms
13  ae14-0.was02-96cbe-1a.ntwk.msn.net (191.234.82.33) 96.5ms
**  [neglected] no reply packets received from TTL 14
15  ae31-0.ch1-96c-1b.ntwk.msn.net (191.234.82.115) 125.7ms
**  [neglected] no reply packets received from TTLs 16 through 20
21  100.73.132.20 114.1ms
**  [neglected] no reply packets received from TTLs 22 through 28
29  [target open] 137.135.178.35:3389 113.3ms

 
