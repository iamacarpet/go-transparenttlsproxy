# Transparent TLS Proxy

This app builds into a proof of concept transparent TLS forward proxy.

It is by no means complete, secure or performant.

Based on the work at github.com/google/tcpproxy

Just like for a transparent HTTP proxy using Squid, redirect the SSL traffic that is heading outbound to the internet on port 443 to this app instead (port 3143).

It doesn't intend to MITM TLS traffic in the traditional sense and performs no crypto functions, it simply uses SNI to log and route the requests accordingly, passing the raw connection on to the destination to perform the crypto.

Think of it like the HTTPS proxy CONNECT with Squid, but without the need to configure the clients.

The data it is possible to log is roughtly the same as HTTPS CONNECT with Squid, but in this POC we don't log duration or bytes transferred.

EDIT: Apprently I'm an idiot and Squid already supports this since 3.5

```
https_port 3130 intercept ssl-bump
ssl_bump peek all
ssl_bump splice all
```