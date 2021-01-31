# TcpHerald v1.11
This Linux program is a proxy server that joins together pairs of incoming TCP
connections. It listens simultaneously on two ports (_supply_ and _demand_) and
connects any new client on the _demand_ port with a client waiting on the
_supply_ port.

If the _driver_ port command line parameter is provided, then the number of
connections waiting on the _demand_ port is sent to all clients connected to the
_driver_ port.

```
Usage: ./tcpherald [options] supply-port demand-port [driver-port]
Options:
      --brief         Print brief information (default).
  -h  --help          Display this usage information.
  -p  --period        Driver refresh period in seconds (30).
  -t  --timeout       Connection idle timeout in seconds (60).
      --verbose       Print verbose information.
  -v  --version       Show version information.
```
