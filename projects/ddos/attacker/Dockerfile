FROM ubuntu:latest
RUN apt-get update && apt-get install -y apache2-utils
COPY attack.sh /usr/local/bin/attack.sh
CMD ["bash", "/usr/local/bin/attack.sh"]
