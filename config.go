package wapsnmp

import (
	"fmt"
	"net"
	"time"
)

//go:generate stringer -type=SNMPError
type SNMPError uint8 // SNMPError is the type for standard SNMP errors.

// SNMP Errors
const (
	NoError             SNMPError = iota // No error occurred. This code is also used in all request PDUs, since they have no error status to report.
	TooBig                               // The size of the Response-PDU would be too large to transport.
	NoSuchName                           // The name of a requested object was not found.
	BadValue                             // A value in the request didn't match the structure that the recipient of the request had for the object. For example, an object in the request was specified with an incorrect length or type.
	ReadOnly                             // An attempt was made to set a variable that has an Access value indicating that it is read-only.
	GenErr                               // An error occurred other than one indicated by a more specific error code in this table.
	NoAccess                             // Access was denied to the object for security reasons.
	WrongType                            // The object type in a variable binding is incorrect for the object.
	WrongLength                          // A variable binding specifies a length incorrect for the object.
	WrongEncoding                        // A variable binding specifies an encoding incorrect for the object.
	WrongValue                           // The value given in a variable binding is not possible for the object.
	NoCreation                           // A specified variable does not exist and cannot be created.
	InconsistentValue                    // A variable binding specifies a value that could be held by the variable but cannot be assigned to it at this time.
	ResourceUnavailable                  // An attempt to set a variable required a resource that is not available.
	CommitFailed                         // An attempt to set a particular variable failed.
	UndoFailed                           // An attempt to set a particular variable as part of a group of variables failed, and the attempt to then undo the setting of other variables was not successful.
	AuthorizationError                   // A problem occurred in authorization.
	NotWritable                          // The variable cannot be written or created.
	InconsistentName                     // The name in a variable binding specifies a variable that does not exist.
)

// SnmpV3MsgFlags contains various message flags to describe Authentication, Privacy, and whether a report PDU must be sent.
type SnmpV3MsgFlags uint8

// Possible values of SnmpV3MsgFlags
const (
	NoAuthNoPriv   SnmpV3MsgFlags = 0x0 // No authentication, and no privacy
	AuthNoPriv     SnmpV3MsgFlags = 0x1 // Authentication and no privacy
	AuthPriv       SnmpV3MsgFlags = 0x3 // Authentication and privacy
	Reportable     SnmpV3MsgFlags = 0x4 // Report PDU must be sent.
	AuthPrivReport SnmpV3MsgFlags = 0x7 //Authentication and privacy + report PDU
)

// SnmpV3SecurityModel describes the security model used by a SnmpV3 connection
type SnmpV3SecurityModel int

// UserSecurityModel is the only SnmpV3SecurityModel currently implemented.
const (
	UserSecurityModel SnmpV3SecurityModel = 0x03
)

type V3user struct {
	User    string
	AuthAlg string //MD5 or SHA1
	AuthPwd string
	PrivAlg string //AES or DES
	PrivPwd string
}

// The object type that lets you do SNMP requests.
type WapSNMP struct {
	Target    string        // Target device for these SNMP events.
	Community string        // Community to use to contact the device.
	Version   SNMPVersion   // SNMPVersion to encode in the packets.
	timeout   time.Duration // Timeout to use for all SNMP packets.
	retries   int           // Number of times to retry an operation.
	conn      net.Conn      // Cache the UDP connection in the object.
	//SNMP V3 variables
	User         string
	AuthAlg      string //MD5 or SHA1
	AuthPwd      string
	PrivAlg      string //AES or DES
	PrivPwd      string
	engineID     string
	MessageFlags SnmpV3MsgFlags
	//V3 temp variables
	AuthKey     string
	PrivKey     string
	engineBoots int32
	engineTime  int32
	desIV       uint32
	aesIV       int64
	Trapusers   []V3user
}

const (
	bufSize    int    = 16384
	maxMsgSize int    = 65500
	SNMP_AES   string = "AES"
	SNMP_DES   string = "DES"
	SNMP_SHA1  string = "SHA1"
	SNMP_MD5   string = "MD5"
)

// NewWapSNMP creates a new WapSNMP object. Opens a udp connection to the device that will be used for the SNMP packets.
func NewWapSNMP(target, community string, version SNMPVersion, timeout time.Duration, retries int) (*WapSNMP, error) {
	targetPort := fmt.Sprintf("%s:161", target)
	conn, err := net.DialTimeout("udp", targetPort, timeout)
	if err != nil {
		return nil, fmt.Errorf(`error connecting to ("udp", "%s") : %s`, targetPort, err)
	}
	return &WapSNMP{
		Target:    target,
		Community: community,
		Version:   version,
		timeout:   timeout,
		retries:   retries,
		conn:      conn,
	}, nil
}

func NewWapSNMPv3(w *WapSNMP, timeout time.Duration, retries int) (*WapSNMP, error) {
	if w.MessageFlags != NoAuthNoPriv && w.MessageFlags != AuthPrivReport {
		return nil, fmt.Errorf(`Currently only NoAuthNoPriv(0x00) and AuthPrivReport(0x07) message flags are implemented`)
	}

	if w.MessageFlags == AuthPrivReport {
		if w.AuthAlg != SNMP_MD5 && w.AuthAlg != SNMP_SHA1 {
			return nil, fmt.Errorf(`Invalid auth algorithm %s, needs SHA1 or MD5`, w.AuthAlg)
		}
		if w.PrivAlg != SNMP_AES && w.PrivAlg != SNMP_DES {
			return nil, fmt.Errorf(`Invalid priv algorithm %s, needs AES or DES`, w.PrivAlg)
		}
	}

	targetPort := fmt.Sprintf("%s:161", w.Target)
	conn, err := net.DialTimeout("udp", targetPort, timeout)
	if err != nil {
		return nil, fmt.Errorf(`error connecting to ("udp", "%s") : %s`, targetPort, err)
	}
	return &WapSNMP{
		Target:       w.Target,
		Version:      SNMPv3,
		timeout:      timeout,
		retries:      retries,
		conn:         conn,
		User:         w.User,
		AuthAlg:      w.AuthAlg,
		AuthPwd:      w.AuthPwd,
		AuthKey:      w.AuthKey,
		PrivAlg:      w.AuthAlg,
		PrivPwd:      w.PrivPwd,
		PrivKey:      w.PrivKey,
		MessageFlags: w.MessageFlags,
	}, nil
}

/* NewWapSNMPOnConn creates a new WapSNMP object from an existing net.Conn.

It does not check if the provided target is valid.*/
func NewWapSNMPOnConn(target, community string, version SNMPVersion, timeout time.Duration, retries int, conn net.Conn) *WapSNMP {
	return &WapSNMP{
		Target:    target,
		Community: community,
		Version:   version,
		timeout:   timeout,
		retries:   retries,
		conn:      conn,
	}
}
