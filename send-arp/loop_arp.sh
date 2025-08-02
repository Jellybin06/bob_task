#!/bin/bash

while true; do
    echo "send-arp-test starting..."
    
    sudo ./send-arp-test wlan0 10.3.3.3 10.3.3.1 &
    PID=$!

    sleep 3

    if ps -p $PID > /dev/null; then
        echo "restart program."
        sudo kill -9 $PID
    else
        echo "program finished!"
    fi

    sleep 1
done

