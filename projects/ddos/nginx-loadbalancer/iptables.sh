
#/bin/bash

iptables -A INPUT -p tcp --dport 80 -m limit --limit 5/second --limit-burst 200 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j LOG --log-prefix "Potential DDoS: "
iptables -A INPUT -p tcp --dport 80 -j DROP
