ettercap-with-ping
==================

Ettercap with added ping and geolocation lookup for active connections. Uses free GeoLite2-City database from maxminddb (http://dev.maxmind.com/geoip/geoip2/geolite2/).

Developed to intercept traffic for online gaming from consoles like xbox 360, and ping peer connected divices to determine network latency that could affect lag in onling games.

Added command line options:

-g --geoip2 <file>   to specify location of GeoLite2-City.mmdb file, default is /usr/local/lib/GeoLite2-City.mmdb

-x --ping <count>    to specify the number of ping packets to send, default is 5

-X --interval <usec> to specify the ping timeout in microseconds, default is 500000 (0.5 seconds)


Added text UI commands:

(xX) lists active connections, pings any remote hosts, and finds geolocation info using the geolite2 database

(aA) lists active connections and finds geolocation info using the geolite2 database


Dependencies:

Needs MaxMind C API (http://dev.maxmind.com/geoip/geoip2/downloadable/)

Needs MaxMind GeoLite2-City.mmdb database (http://dev.maxmind.com/geoip/geoip2/geolite2/)

Example Usage:

Using ettercap ARP poisoning to intercept all xbox live traffic.

ettercap -Tq -i eth0 -M arp:remote /192.168.1.100/ /192.168.1.254/ -P autoadd 2>/dev/null

Active connection list:

    192.168.1.100:3074  -    82.23.12.XXX:3074  U active  TX: 1420176 RX: 0 PING DST min/avg/max: 37.4/39.6/41.7 ms loss: 0%, United Kingdom, England, Dunstable
    192.168.1.100:3074  -   88.108.47.XXX:3074  U active  TX: 3768 RX: 0 PING DST No Reply, United Kingdom
    192.168.1.100:3074  - 212.140.202.XXX:3074  U active  TX: 1728 RX: 0 PING DST No Reply, United Kingdom, England, Kings Lynn
    192.168.1.100:3074  -  109.13.184.XXX:3074  U active  TX: 105822 RX: 0 PING DST No Reply, France, Auvergne, Joze
    192.168.1.100:3074  -  151.226.57.XXX:3074  U active  TX: 3888 RX: 0 PING DST min/avg/max: 28.2/28.3/28.6 ms loss: 0%, United Kingdom, England, Birmingham
    192.168.1.100:3074  -     2.30.232.XXX:1024  U active  TX: 3888 RX: 0 PING DST No Reply, United Kingdom, England, Kidderminster
    192.168.1.100:3074  -      78.34.2.XXX:61355 U active  TX: 99316 RX: 0 PING DST No Reply, Germany, North Rhine-Westphalia, Cologne
    192.168.1.100:3074  -    65.55.42.XXX:3074  U active  TX: 15239 RX: 0 PING DST min/avg/max: 155.5/155.9/156.8 ms loss: 0%, United States, Washington, Redmond
    192.168.1.100:3074  -    136.179.4.XXX:3074  U active  TX: 23349 RX: 0 PING DST No Reply, United States, Nevada, Las Vegas
     82.21.19.XXX:33263 -   192.168.1.XXX:3074  U active  TX: 3422 RX: 3314 PING SRC No Reply, United Kingdom, England, Portsmouth
    192.168.1.100:3074  -      78.34.2.XXX:3074  U active  TX: 7120 RX: 0 PING DST No Reply, Germany, North Rhine-Westphalia, Cologne
    86.16.133.XXX:3074  -   192.168.1.XXX:3074  U active  TX: 1094 RX: 938 PING SRC No Reply, United Kingdom, England, Bristol
    82.34.187.XXX:3074  -   192.168.1.XXX:3074  U active  TX: 938 RX: 1094 PING SRC No Reply, United Kingdom, England, Nailsea
