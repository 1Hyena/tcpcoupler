# TcpHerald v1.02
This Linux program is a proxy server that joins together pairs of incoming TCP
connections. It listens simultaneously on two ports (_supply_ and _demand_) and
connects any new client on the _demand_ port with a client waiting on the
_supply_ port.

```
Usage: ./tcpherald [options] supply-port demand-port
Options:
      --brief         Print brief information (default).
  -h  --help          Display this usage information.
      --verbose       Print verbose information.
  -v  --version       Show version information.
```
