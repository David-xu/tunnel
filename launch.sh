#!/bin/bash

#if [[ $# -eq 1 ]] ; then

#fi

if [[ "$1" = "server" ]] ; then
    ./rottenNut -d --mode=server --serv_ip=127.0.0.1 --port_list=40000,40001,50002,50003 --transport_send_bps=100000
elif [[ "$1" = "socks5" ]] ; then
    ./ref/microsocks-master/microsocks -p 3001 > /var/log/microsocks.log &
elif [[ "$1" = "stop" ]] ; then
    kill $(pidof rottenNut)
    kill $(pidof microsocks)
elif [[ "$1" = "rmlog" ]] ; then
    rm -rf /var/log/rottenNut.log
    rm -rf /var/log/microsocks.log
else
    echo "invalid param"
fi

