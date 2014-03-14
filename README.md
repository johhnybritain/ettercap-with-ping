ettercap-with-ping
==================

ettercap with added ping and geolocation lookup for active connections. Uses free GeoLite2-City database from maxminddb (http://dev.maxmind.com/geoip/geoip2/geolite2/).

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

