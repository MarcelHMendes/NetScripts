#!/bin/bash

URL="http://localhost"  # Replace with your target URL

while true; do
    curl -s "$URL"  # The -s flag silences progress output
    sleep 2         # Wait for 2 seconds before the next request
done
