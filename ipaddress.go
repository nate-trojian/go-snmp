package wapsnmp

/*

  Encode decode Ip address.

*/

import (
	"net"
)

// The SNMP object identifier type.
type IPAddress []byte

func ParseIPv4(ip string) (IPAddress, error) {
	ipAddr := net.ParseIP(ip)

	return IPAddress([]byte(ipAddr)[12:]), nil
}
