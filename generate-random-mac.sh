#!/bin/bash

set -eu

if [ $EUID -ne 0 ]; then
    echo "$0 is not running as root. Try using sudo."
    exit 2
fi

MAC=$(hexdump -n3 -e'/3 "08:00:27" 3/1 ":%02X"' /dev/random)

ip link show
echo "--------"

read -p "Enter Interface that you want to change the mac adrress:" interface

echo "$interface - New mac: $MAC"
read -p "Are you sure? (y/n)" check

if [ $check != "y" ] && [ $check != "Y" ];
then
    exit
fi

if ! macchanger -v COMMAND &> /dev/null
then
    echo "Macchanger could not be found"
    echo "Trying to install macchanger..."
    apt install macchanger
fi

if macchanger -v COMMAND &> /dev/null
then
    macchanger -m $MAC $interface
elif ifconfig --help COMMAND &> /dev/null
    then
        ifconfig $interface down
        ifconfig $interface hw ether $MAC
        ifconfig $interface up
    else
        echo "MAC update failed"
fi
