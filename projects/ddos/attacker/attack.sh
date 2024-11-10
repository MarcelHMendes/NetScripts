#!/bin/bash

# Continuously send requests to the web server
while true; do
    ab -n 1000 -c 10 http://load_balancer/ > /dev/null 2>&1
done
