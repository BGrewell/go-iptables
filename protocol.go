package iptables

// Protocol represents the default tables
type Protocol string

const (
	ProtocolAll  Protocol = "all"
	ProtocolIP   Protocol = "ip"
	ProtocolIPv6 Protocol = "ipv6"
	ProtocolICMP Protocol = "icmp"
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolSCTP Protocol = "sctp"
)
