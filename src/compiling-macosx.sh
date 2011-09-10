#!/bin/sh
#
# this simple & wrong script has been written because CMake for 
# macosx ports are not updated with the release required by 
# Janus CMakeLists.txt
#
# therefore a simple sequence of gcc had solved well, but, the 
# goal was simply compiling janus for MACOSX

if [ "$1" = "clean" ]; then
    rm -f *.o janus-macosx
fi

gcc -c tun/tun-freebsd.c 
gcc -c packet_queue.c 
gcc -c os_cmds.c
gcc -I /opt/local/include/ -c janus.c 
gcc -I /opt/local/include/ -c main.c 

gcc *.o -L/opt/local/lib -levent -lpcap -o janus-macosx 


