package wapsnmp

import (
	"fmt"
	"testing"
)

func TestParseIPv4(t *testing.T) {
	ip := "127.0.1.2"

	actualIP, _ := ParseIPV4(ip)
	fmt.Println(actualIP)
}
