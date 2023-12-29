# TCP Coupler v1.14
This Linux program is a proxy server that joins together pairs of incoming TCP
connections. It listens simultaneously on two ports (_supply_ and _demand_) and
connects any new client on the _demand_ port with a client waiting on the
_supply_ port.

```
Usage: ./tcpcoupler [options] supply-port demand-port [driver-port]
Options:
      --brief         Print brief information (default).
  -h  --help          Display this usage information.
  -p  --period        Driver refresh period in seconds (30).
  -t  --timeout       Connection idle timeout in seconds (60).
      --verbose       Print verbose information.
  -v  --version       Show version information.
```

# Driver Port
If the _driver_ port command line parameter is provided, then the number of
connections waiting on the _demand_ port is sent to all clients connected to the
_driver_ port.

Below is given an example setup that makes use of the _driver-port_ parameter.
Let's say a _tcpcoupler_ instance is running on the _remotehost_ domain, having
port _5000_ for its _suppy-port_, port _6000_ for its _demand-port_ and port
_7000_ for its _driver-port_. We now wish to provide some TCP service running on
_localhost_ port _4000_ from the mentioned remote host. To do so, we utilize the
_netcat_, _xargs_ and [tcpnipple](https://github.com/1Hyena/tcpnipple) tools.

```
nc remotehost 7000 | \
xargs -I {} -P 0 ./tcpnipple -c {} localhost 4000 remotehost 5000
```

Every time a new connection is made to _remotehost:6000_, the number of waiting
connections is sent via the _driver-port_ to the _netcat_ instance. The latter
will forward that number to _xargs_ which in turn spawns _tcpnipple_, connecting
the server on _localhost:4000_ to the server on _remotehost:5000_.
