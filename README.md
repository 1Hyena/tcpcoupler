# tcpherald
This Linux program is a proxy server that joins together pairs of incoming TCP
connections. It listens simultaneously on two ports (_supply_ and _demand_) and
connects any new client on the _demand_ port with a client waiting on the
_supply_ port.
