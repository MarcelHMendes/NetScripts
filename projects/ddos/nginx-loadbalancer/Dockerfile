FROM nginx:alpine

# Install iptables
RUN apk add --no-cache iptables

COPY iptables.sh /usr/local/bin/iptables-rules.sh

RUN chmod u+x /usr/local/bin/iptables-rules.sh
