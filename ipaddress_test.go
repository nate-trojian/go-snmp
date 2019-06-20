package wapsnmp

import (
	"reflect"
	"testing"
)

func TestParseIPv4(t *testing.T) {
	ip := "127.0.1.2"
	expectedIPBytes := IPAddress([]byte{127, 0, 1, 2})

	actualIP := ParseIPv4(ip)

	if !reflect.DeepEqual(expectedIPBytes, actualIP) {
		t.Errorf("Failed to parse %v ! EncodeInteger => %v Expected %v", ip, actualIP, expectedIPBytes)
	}
}
