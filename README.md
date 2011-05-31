# Janus is a portable, unified and lightweight interface for mitm applications over the routing table.

It acts like a deamon and offers two simple stream sockets, one for input and one for the output traffic manipulations.
Over this sockets, before a packet, it's always appended it's size (16bit), and Janus expects to receive data back with this precise format.
The code is a portable and optimized rewrite of a first idea implemented in SniffJoke software written by Claudio Agosti.
Janus overrides the actual routing table, creating a fake gateway with the aim to block packets after the kernel (on outgoing traffic) and before the kernel (on incoming traffic).

# Requirements

    cmake, gcc, iptables, route, sed

# Below are some examples starting from this common routing table:

    root@linux# route -n
    Kernel IP routing table
    Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
    94.23.192.28    10.196.136.1    255.255.255.255 UGH   0      0        0 eth0
    94.228.214.57   10.196.135.1    255.255.255.255 UGH   0      0        0 eth1
    10.196.135.0    0.0.0.0         255.255.255.0   U     0      0        0 eth0
    10.196.136.0    0.0.0.0         255.255.255.0   U     0      0        0 eth1
    0.0.0.0         10.196.136.1    0.0.0.0         UG    0      0        0 eth0


#1st Example: Simple immediate exection (by default Janus executes a mitm over the default gateway)
    root@linux# janus
    Janus is now going to background, use SIGTERM to stop it.

    root@linux# route -n
    Kernel IP routing table
    Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
    94.23.192.28    10.196.135.1    255.255.255.255 UGH   0      0        0 eth0
    94.228.214.57   10.196.136.1    255.255.255.255 UGH   0      0        0 eth1
    10.196.135.0    0.0.0.0         255.255.255.0   U     0      0        0 eth0
    10.196.136.0    0.0.0.0         255.255.255.0   U     0      0        0 eth1
    212.77.1.1      0.0.0.0         255.255.255.255 UH    0      0        0 janus0
    0.0.0.0         212.77.1.1      0.0.0.0         UG    0      0        0 janus0


#2nd Example: Custom execution (single janus instance)
    root@linux# janus --net 94.23.192.28/255.255.255.255
    Janus is now going to background, use SIGTERM to stop it.

    root@linux# route -n
    Kernel IP routing table
    Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
    94.23.192.28    212.77.1.1      255.255.255.255 UGH   0      0        0 janus0
    94.228.214.57   10.196.136.1    255.255.255.255 UGH   0      0        0 eth1
    10.196.135.0    0.0.0.0         255.255.255.0   U     0      0        0 eth0
    10.196.136.0    0.0.0.0         255.255.255.0   U     0      0        0 eth1
    212.77.1.1      0.0.0.0         255.255.255.255 UH    0      0        0 janus0
    0.0.0.0         10.196.135.1    0.0.0.0         UG    0      0        0 eth0

#3rd Example: Custom execution (multiple janus instance, two for example)
    root@linux# janus --net 94.23.192.28/255.255.255.255 --listen-port-in 4001 --listen-port-out 4002
    Janus is now going to background, use SIGTERM to stop it.

    root@linux# janus --net 94.228.214.57/255.255.255.255 --listen-port-in 5001 --listen-port-out 5002
    Janus is now going to background, use SIGTERM to stop it.

    root@linux# route -n
    Kernel IP routing table
    Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
    94.23.192.28    212.77.1.1      255.255.255.255 UGH   0      0        0 janus0
    94.228.214.57   212.77.1.2      255.255.255.255 UGH   0      0        0 janus1
    10.196.135.0    0.0.0.0         255.255.255.0   U     0      0        0 eth0
    10.196.136.0    0.0.0.0         255.255.255.0   U     0      0        0 eth1
    212.77.1.1      0.0.0.0         255.255.255.255 UH    0      0        0 janus0
    212.77.1.2      0.0.0.0         255.255.255.255 UH    0      0        0 janus1
    0.0.0.0         10.196.135.1    0.0.0.0         UG    0      0        0 eth0

## Client POC

% This is a proof of concept written in Erlang that implements a simple Janus Client.
% It shows how simple is the Janus interface executing a simple packet-echo.
%
% Usage: erl -compile janus_client_poc && erl --noshell -s janus_client_poc start
%

-module(janus_client_poc).
-export([start/0]).

start() ->
    JanusHost = "127.0.0.1",
    JanusPort1 = 10203,
    JanusPort2 = 30201,
    spawn(fun() -> connect(JanusHost, JanusPort1) end),
    spawn(fun() -> connect(JanusHost, JanusPort2) end).

connect(Host, Port) ->
    {ok, Socket} = gen_tcp:connect(Host, Port, [{active,false}, {packet,0}]),
    echo_loop(Socket).

echo_loop(Socket) ->
    case gen_tcp:recv(Socket, 0) of
        {ok, Data} ->
            % eventual packet mangling activity
            gen_tcp:send(Socket, Data),
            echo_loop(Socket);
        {error, _} ->
            ok
    end.


## Installed files (paths may vary on your system)

Janus binary /usr/local/sbin/janus

Janus man page /usr/local/man/man1/janus.1

Official Janus page:
    https://github.com/evilaliv3/janus

# GPG public keys

    X-2:~ X$ gpg --keyserver pgp.mit.edu --recv-key D9A950DE
    X-2:~ X$ gpg --fingerprint --list-keys D9A950DE
    pub   1024D/D9A950DE 2009-05-10 [expires: 2014-05-09]
          Key fingerprint = C1ED 5C8F DB6A 1C74 A807  5695 91EC 9BB8 D9A9 50DE
    uid                  Giovanni Pellerano <giovanni.pellerano@evilaliv3.org>
    sub   4096g/50A7F150 2009-05-10 [expires: 2014-05-09]

    X-2:~ X$ gpg --keyserver pgp.mit.edu --recv-key C6765430
    X-2:~ X$ gpg --fingerprint --list-keys C6765430
    pub   1024D/C6765430 2009-08-25 [expires: 2011-08-25]
          Key fingerprint = 341F 1A8C E2B4 F4F4 174D  7C21 B842 093D C676 5430
    uid                  vecna <vecna@s0ftpj.org>
    uid                  vecna <vecna@delirandom.net>
    sub   3072g/E8157737 2009-08-25 [expires: 2011-08-25]
