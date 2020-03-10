// Package wapsnmp provides an SNMP query library.
package wapsnmp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"reflect"
	"strings"
	"time"
)

func password_to_key(password string, engineID string, hash_alg string) string {
	h := sha1.New()
	if hash_alg == "MD5" {
		h = md5.New()
	}

	count := 0
	plen := len(password)
	repeat := 1048576 / plen
	remain := 1048576 % plen
	for count < repeat {
		io.WriteString(h, password)
		count++
	}
	if remain > 0 {
		io.WriteString(h, string(password[:remain]))
	}
	ku := string(h.Sum(nil))
	//fmt.Printf("ku=% x\n", ku)

	h.Reset()
	io.WriteString(h, ku)
	io.WriteString(h, engineID)
	io.WriteString(h, ku)
	localKey := h.Sum(nil)
	//fmt.Printf("localKey=% x\n", localKey)

	return string(localKey)
}

// Generate a valid SNMP request ID.
func getRandomRequestID() int {
	return int(rand.Int31())
}

// poll sends a packet and wait for a response. Both operations can timeout, they're retried up to retries times.
func poll(conn net.Conn, toSend []byte, respondBuffer []byte, retries int, timeout time.Duration) (int, error) {
	var err error
	for i := 0; i < retries+1; i++ {
		deadline := time.Now().Add(timeout)

		if err = conn.SetWriteDeadline(deadline); err != nil {
			log.Printf("Couldn't set write deadline. Retrying. Retry %d/%d\n", i, retries)
			continue
		}
		if _, err = conn.Write(toSend); err != nil {
			log.Printf("Couldn't write. Retrying. Retry %d/%d\n", i, retries)
			continue
		}

		deadline = time.Now().Add(timeout)
		if err = conn.SetReadDeadline(deadline); err != nil {
			log.Printf("Couldn't set read deadline. Retrying. Retry %d/%d\n", i, retries)
			continue
		}

		numRead := 0
		if numRead, err = conn.Read(respondBuffer); err != nil {
			//log.Printf("Couldn't read. Retrying. Retry %d/%d\n", i, retries)
			continue
		}

		return numRead, nil
	}
	return 0, err
}

// Set sends an SNMP set request to change the value associated with an oid.
func (w WapSNMP) Set(oid Oid, value interface{}) (interface{}, error) {
	requestID := getRandomRequestID()
	req, err := EncodeSequence([]interface{}{Sequence, int(w.Version), w.Community,
		[]interface{}{AsnSetRequest, requestID, 0, 0,
			[]interface{}{Sequence,
				[]interface{}{Sequence, oid, value}}}})
	if err != nil {
		return nil, err
	}

	response := make([]byte, bufSize, bufSize)
	numRead, err := poll(w.conn, req, response, w.retries, w.timeout)
	if err != nil {
		return nil, err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		return nil, err
	}

	// Fetch the varbinds out of the packet.
	respPacket := decodedResponse[3].([]interface{})
	if err := respPacket[2].(int); err != 0 {
		return nil, fmt.Errorf("Error in setting snmp value: %s \n", SNMPError(err))
	}

	varbinds := respPacket[4].([]interface{})
	result := varbinds[1].([]interface{})[2]

	return result, nil
}

// Get sends an SNMP get request requesting the value for an oid.
func (w WapSNMP) Get(oid Oid) (interface{}, error) {
	requestID := getRandomRequestID()
	req, err := EncodeSequence([]interface{}{Sequence, int(w.Version), w.Community,
		[]interface{}{AsnGetRequest, requestID, 0, 0,
			[]interface{}{Sequence,
				[]interface{}{Sequence, oid, nil}}}})
	if err != nil {
		return nil, err
	}

	response := make([]byte, bufSize, bufSize)
	numRead, err := poll(w.conn, req, response, w.retries, w.timeout)
	if err != nil {
		return nil, err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		return nil, err
	}

	// Fetch the varbinds out of the packet.
	respPacket := decodedResponse[3].([]interface{})
	varbinds := respPacket[4].([]interface{})
	result := varbinds[1].([]interface{})[2]

	if result == nil {
		return nil, fmt.Errorf("%v", varbinds[1].([]interface{})[3])
	}

	return result, nil
}

// GetMultiple issues a single GET SNMP request requesting multiple values
func (w WapSNMP) GetMultiple(oids []Oid) (map[string]interface{}, error) {
	requestID := getRandomRequestID()

	varbinds := []interface{}{Sequence}
	for _, oid := range oids {
		varbinds = append(varbinds, []interface{}{Sequence, oid, nil})
	}
	req, err := EncodeSequence([]interface{}{Sequence, int(w.Version), w.Community,
		[]interface{}{AsnGetRequest, requestID, 0, 0, varbinds}})

	if err != nil {
		return nil, err
	}

	response := make([]byte, bufSize, bufSize)
	numRead, err := poll(w.conn, req, response, w.retries, w.timeout)
	if err != nil {
		return nil, err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		return nil, err
	}

	// Find the varbinds
	respPacket := decodedResponse[3].([]interface{})
	respVarbinds := respPacket[4].([]interface{})

	result := make(map[string]interface{})
	for _, v := range respVarbinds[1:] { // First element is just a sequence
		oid := v.([]interface{})[1].(string)
		value := v.([]interface{})[2]
		if value == nil {
			result[oid] = map[string]interface{}{
				"value": nil,
				"error": v.([]interface{})[3],
			}
		} else {
			result[oid] = map[string]interface{}{
				"value": value,
				"error": nil,
			}
		}
	}

	return result, nil
}

/* SNMP V3 requires a discover packet being sent before a request being sent,
   so that agent's engineID and other parameters can be automatically detected
*/
func (w *WapSNMP) Discover() error {
	msgID := getRandomRequestID()
	requestID := getRandomRequestID()
	v3Header, _ := EncodeSequence([]interface{}{Sequence, "", 0, 0, "", "", ""})
	flags := string([]byte{4})
	USM := 0x03
	req, err := EncodeSequence([]interface{}{
		Sequence, int(w.Version),
		[]interface{}{Sequence, msgID, maxMsgSize, flags, USM},
		string(v3Header),
		[]interface{}{Sequence, "", "",
			[]interface{}{AsnGetRequest, requestID, 0, 0, []interface{}{Sequence}}}})
	if err != nil {
		fmt.Printf("Error encoding in discover:%v\n", err)
		panic(err)
	}

	response := make([]byte, bufSize)
	numRead, err := poll(w.conn, req, response, w.retries, w.timeout)
	if err != nil {
		return err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		fmt.Printf("Error decoding discover:%v\n", err)
		panic(err)
	}

	v3HeaderStr := decodedResponse[3].(string)
	v3HeaderDecoded, err := DecodeSequence([]byte(v3HeaderStr))
	if err != nil {
		fmt.Printf("Error 2 decoding:%v\n", err)
		return err
	}

	w.engineID = v3HeaderDecoded[1].(string)
	w.engineBoots = int32(v3HeaderDecoded[2].(int))
	w.engineTime = int32(v3HeaderDecoded[3].(int))
	w.aesIV = rand.Int63()
	w.desIV = rand.Uint32()

	//keys
	if w.AuthKey == "" && w.MessageFlags != NoAuthNoPriv {
		w.AuthKey = password_to_key(w.AuthPwd, w.engineID, w.AuthAlg)
	}

	if w.PrivKey == "" && w.MessageFlags != NoAuthNoPriv {
		privKey := password_to_key(w.PrivPwd, w.engineID, w.AuthAlg)
		w.PrivKey = string(([]byte(privKey))[0:16])
	}

	return nil
}

func EncryptDESCBC(dst, src, key, iv []byte) error {
	desBlockEncrypter, err := des.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	desEncrypter := cipher.NewCBCEncrypter(desBlockEncrypter, iv)
	desEncrypter.CryptBlocks(dst, src)
	return nil
}

func DecryptDESCBC(dst, src, key, iv []byte) error {
	desBlockEncrypter, err := des.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	desDecrypter := cipher.NewCBCDecrypter(desBlockEncrypter, iv)
	desDecrypter.CryptBlocks(dst, src)
	return nil
}

func EncryptAESCFB(dst, src, key, iv []byte) error {
	aesBlockEncrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(dst, src)
	return nil
}

func DecryptAESCFB(dst, src, key, iv []byte) error {
	aesBlockDecrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(dst, src)
	return nil
}

func strXor(s1, s2 string) string {
	if len(s1) != len(s2) {
		panic("strXor called with two strings of different length\n")
	}
	n := len(s1)
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = s1[i] ^ s2[i]
	}
	return string(b)
}

func (w WapSNMP) auth(wholeMsg string) string {
	//Auth
	padLen := 64 - len(w.AuthKey)
	eAuthKey := w.AuthKey + strings.Repeat("\x00", padLen)
	ipad := strings.Repeat("\x36", 64)
	opad := strings.Repeat("\x5C", 64)
	k1 := strXor(eAuthKey, ipad)
	k2 := strXor(eAuthKey, opad)
	h := sha1.New()
	if w.AuthAlg == "MD5" {
		h = md5.New()
	}
	io.WriteString(h, k1+wholeMsg)
	tmp1 := string(h.Sum(nil))
	h.Reset()
	io.WriteString(h, k2+tmp1)
	msgAuthParam := string(h.Sum(nil)[:12])
	return msgAuthParam
}

func (w WapSNMP) encrypt(payload string) (string, string) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, w.engineBoots)
	if w.PrivAlg == SNMP_AES {
		buf2 := new(bytes.Buffer)
		binary.Write(buf2, binary.BigEndian, w.engineTime)
		buf3 := new(bytes.Buffer)
		w.aesIV += 1
		binary.Write(buf3, binary.BigEndian, w.aesIV)
		privParam := string(buf3.Bytes())
		iv := string(buf.Bytes()) + string(buf2.Bytes()) + privParam

		// AES Encrypt
		encrypted := make([]byte, len(payload))
		err := EncryptAESCFB(encrypted, []byte(payload), []byte(w.PrivKey), []byte(iv))
		if err != nil {
			panic(err)
		}
		return string(encrypted), privParam
	} else {
		desKey := w.PrivKey[:8]
		preIV := w.PrivKey[8:16]
		buf2 := new(bytes.Buffer)
		w.desIV += 1
		binary.Write(buf2, binary.BigEndian, w.desIV)
		privParam := string(buf.Bytes()) + string(buf2.Bytes())
		iv := strXor(preIV, privParam)

		//DES Encrypt
		plen := len(payload)
		//padding
		if (plen % 8) != 0 {
			payload = payload + strings.Repeat("\x00", 8-(plen%8))
		}
		encrypted := make([]byte, len(payload))
		EncryptDESCBC(encrypted, []byte(payload), []byte(desKey), []byte(iv))
		return string(encrypted), privParam
	}
}

func (w WapSNMP) decrypt(payload, privParam string) string {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, w.engineBoots)

	if w.PrivAlg == SNMP_AES {
		buf2 := new(bytes.Buffer)
		binary.Write(buf2, binary.BigEndian, w.engineTime)
		iv := string(buf.Bytes()) + string(buf2.Bytes()) + privParam

		// Decrypt
		decrypted := make([]byte, len(payload))
		err := DecryptAESCFB(decrypted, []byte(payload), []byte(w.PrivKey), []byte(iv))
		if err != nil {
			panic(err)
		}
		return string(decrypted)
	} else {
		desKey := w.PrivKey[:8]
		preIV := w.PrivKey[8:16]
		iv := strXor(preIV, privParam)

		//DES Decrypt
		plen := len(payload)
		if (plen % 8) != 0 {
			panic("DES encrypted payload is not multiple of 8 bytes\n")
		}
		decrypted := make([]byte, len(payload))
		DecryptDESCBC(decrypted, []byte(payload), []byte(desKey), []byte(iv))
		return string(decrypted)
	}

}

// GetNext issues a GETNEXT SNMP request.
func (w *WapSNMP) GetNextV3(oid Oid) (string, interface{}, error) {
	return w.doGetV3(oid, AsnGetNextRequest)
}

// Get
func (w *WapSNMP) GetV3(oid Oid) (interface{}, error) {
	_, val, err := w.doGetV3(oid, AsnGetRequest)
	return val, err
}

// SetV3 sends an SNMP V3 set request to change the value associated with an oid.
func (w *WapSNMP) SetV3(oid Oid, value interface{}) (interface{}, error) {
	msgID := getRandomRequestID()
	requestID := getRandomRequestID()
	req, err := EncodeSequence(
		[]interface{}{Sequence, w.engineID, "",
			[]interface{}{AsnSetRequest, requestID, 0, 0,
				[]interface{}{Sequence,
					[]interface{}{Sequence, oid, value}}}})
	if err != nil {
		panic(err)
	}

	encrypted, privParam := w.encrypt(string(req))

	v3Header, err := EncodeSequence([]interface{}{Sequence, w.engineID,
		int(w.engineBoots), int(w.engineTime), w.User, strings.Repeat("\x00", 12), privParam})
	if err != nil {
		panic(err)
	}

	flags := string([]byte{7})
	USM := 0x03
	packet, err := EncodeSequence([]interface{}{
		Sequence, int(w.Version),
		[]interface{}{Sequence, msgID, maxMsgSize, flags, USM},
		string(v3Header),
		encrypted})
	if err != nil {
		panic(err)
	}
	authParam := w.auth(string(packet))
	finalPacket := strings.Replace(string(packet), strings.Repeat("\x00", 12), authParam, 1)

	response := make([]byte, bufSize)
	numRead, err := poll(w.conn, []byte(finalPacket), response, w.retries, w.timeout)
	if err != nil {
		return nil, err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		fmt.Printf("Error decoding setReq:%v\n", err)
		return nil, err
	}
	/*
		for i, val := range decodedResponse{
			fmt.Printf("Resp:%v:type=%v\n",i,reflect.TypeOf(val));
		}
	*/

	v3HeaderStr := decodedResponse[3].(string)
	v3HeaderDecoded, err := DecodeSequence([]byte(v3HeaderStr))
	if err != nil {
		fmt.Printf("Error 2 decoding:%v\n", err)
		return nil, err
	}

	w.engineID = v3HeaderDecoded[1].(string)
	w.engineBoots = int32(v3HeaderDecoded[2].(int))
	w.engineTime = int32(v3HeaderDecoded[3].(int))
	// skip checking authParam for now
	respAuthParam := v3HeaderDecoded[5].(string)
	respPrivParam := v3HeaderDecoded[6].(string)

	if len(respAuthParam) == 0 || len(respPrivParam) == 0 {
		return nil, fmt.Errorf("Error,response is not encrypted.")
	}

	encryptedResp := decodedResponse[4].(string)
	plainResp := w.decrypt(encryptedResp, respPrivParam)

	pduDecoded, err := DecodeSequence([]byte(plainResp))
	if err != nil {
		fmt.Printf("Error 3 decoding:%v\n", err)
		return nil, err
	}

	// Find the varbinds
	respPacket := pduDecoded[3].([]interface{})
	if err := respPacket[2].(int); err != 0 {
		return nil, fmt.Errorf("Error in setting snmp value: %s \n", SNMPError(err))
	}

	varbinds := respPacket[4].([]interface{})
	result := varbinds[1].([]interface{})[2]

	return result, nil
}

func (w *WapSNMP) marshalV3(req []interface{}) string {
	var finalPacket string
	msgID := getRandomRequestID()
	flags := w.MessageFlags

	header := []interface{}{Sequence, msgID, maxMsgSize, string(flags), int(UserSecurityModel)}

	if flags == NoAuthNoPriv {
		v3Header, _ := EncodeSequence([]interface{}{Sequence, w.engineID,
			int(w.engineBoots), int(w.engineTime), w.User, "", ""})

		packet, err := EncodeSequence([]interface{}{
			Sequence, int(w.Version), header,
			string(v3Header), req})
		if err != nil {
			panic(err)
		}

		finalPacket = string(packet)

	} else { //AuthPrivReport case
		reqEncoded, err := EncodeSequence(req)
		if err != nil {
			panic(err)
		}

		encrypted, privParam := w.encrypt(string(reqEncoded))

		v3Header, err := EncodeSequence([]interface{}{Sequence, w.engineID,
			int(w.engineBoots), int(w.engineTime), w.User, strings.Repeat("\x00", 12), privParam})
		if err != nil {
			panic(err)
		}

		packet, err := EncodeSequence([]interface{}{
			Sequence, int(w.Version), header,
			string(v3Header),
			encrypted})
		if err != nil {
			panic(err)
		}

		authParam := w.auth(string(packet))
		finalPacket = strings.Replace(string(packet), strings.Repeat("\x00", 12), authParam, 1)
	}

	return finalPacket
}

// A function does both GetNext and Get for SNMP V3
func (w *WapSNMP) doGetV3(oid Oid, request BERType) (string, interface{}, error) {
	requestID := getRandomRequestID()
	req := []interface{}{Sequence, w.engineID, "",
		[]interface{}{request, requestID, 0, 0,
			[]interface{}{Sequence,
				[]interface{}{Sequence, oid, nil}}}}

	// Function to apply the right level of security parameters and PDU packet
	finalPacket := w.marshalV3(req)

	response := make([]byte, bufSize)
	numRead, err := poll(w.conn, []byte(finalPacket), response, w.retries, w.timeout)
	if err != nil {
		return "", nil, err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		fmt.Printf("Error decoding getNext:%v\n", err)
		return "", nil, err
	}
	/*
		for i, val := range decodedResponse{
			fmt.Printf("Resp:%v:type=%v\n",i,reflect.TypeOf(val));
		}
	*/

	pduResponse, err := w.unMarshalV3(decodedResponse)
	if err != nil {
		fmt.Printf("Error in unMarshalV3:%v\n", err)
		return "", nil, err
	}

	// Find the varbinds
	respPacket := pduResponse[3].([]interface{})
	varbinds := respPacket[4].([]interface{})
	result := varbinds[1].([]interface{})

	resultOid := result[1].(string)
	resultVal := result[2]

	// Check if the value is string and printable. To distinguish HEX-String from normal string
	if res, ok := resultVal.(string); ok && !IsStringAsciiPrintable(resultVal.(string)){
		return resultOid, fmt.Sprintf("%x", res), nil
	}
	return resultOid, resultVal, nil
}

// A function that does GetMultiple for SNMP V3
func (w *WapSNMP) GetMultipleV3(oids []Oid) (map[string]interface{}, error) {
	requestID := getRandomRequestID()

	varbinds := []interface{}{Sequence}

	for _, oid := range oids {
		varbinds = append(varbinds, []interface{}{Sequence, oid, nil})
	}

	req := []interface{}{Sequence, w.engineID, "",
		[]interface{}{AsnGetRequest, requestID, 0, 0, varbinds}}

	// Function to apply the right level of security parameters and PDU packet
	finalPacket := w.marshalV3(req)

	response := make([]byte, bufSize)
	numRead, err := poll(w.conn, []byte(finalPacket), response, w.retries, w.timeout)
	if err != nil {
		return nil, err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		fmt.Printf("Error decoding GetMultipleV3:%v\n", err)
		return nil, err
	}
	/*
		for i, val := range decodedResponse{
			fmt.Printf("Resp:%v:type=%v\n",i,reflect.TypeOf(val));
		}
	*/

	pduResponse, err := w.unMarshalV3(decodedResponse)
	if err != nil {
		fmt.Printf("Error in unMarshalV3:%v\n", err)
		return nil, err
	}

	// Find the varbinds
	respPacket := pduResponse[3].([]interface{})
	respVarbinds := respPacket[4].([]interface{})

	result := make(map[string]interface{})
	for _, v := range respVarbinds[1:] { // First element is just a sequence
		oid := v.([]interface{})[1].(string)
		value := v.([]interface{})[2]
		if value == nil {
			result[oid] = map[string]interface{}{
				"value": nil,
				"error": v.([]interface{})[3],
			}
		} else {
			// Check if the value is string and printable. To distinguish HEX-String from normal string
			if res, ok := value.(string); ok && !IsStringAsciiPrintable(value.(string)){
				result[oid] = map[string]interface{}{
					"value": fmt.Sprintf("%x", res),
					"error": nil,
				}
			} else {
				result[oid] = map[string]interface{}{
					"value": value,
					"error": nil,
				}
			}
		}
	}

	return result, nil
}

func (w *WapSNMP) unMarshalV3(decodedResponse []interface{}) ([]interface{}, error) {
	v3HeaderStr := decodedResponse[3].(string)
	v3HeaderDecoded, err := DecodeSequence([]byte(v3HeaderStr))
	if err != nil {
		fmt.Printf("Error 2 decoding:%v\n", err)
		return nil, err
	}

	w.engineID = v3HeaderDecoded[1].(string)
	w.engineBoots = int32(v3HeaderDecoded[2].(int))
	w.engineTime = int32(v3HeaderDecoded[3].(int))
	// skip checking authParam for now
	respAuthParam := v3HeaderDecoded[5].(string)
	respPrivParam := v3HeaderDecoded[6].(string)

	if (len(respAuthParam) == 0 || len(respPrivParam) == 0) && w.MessageFlags == AuthPrivReport {
		return nil, fmt.Errorf("Error,response is not encrypted.")
	}
	var pduResponse []interface{}

	if w.MessageFlags == AuthPrivReport {
		encryptedResp := decodedResponse[4].(string)
		plainResp := w.decrypt(encryptedResp, respPrivParam)

		pduDecoded, err := DecodeSequence([]byte(plainResp))
		if err != nil {
			fmt.Printf("Error 3 decoding:%v\n", err)
			return nil, err
		}

		pduResponse = pduDecoded

	} else {
		pduResponse = decodedResponse[4].([]interface{})
	}

	return pduResponse, nil
}

// GetNext issues a GETNEXT SNMP request.
func (w WapSNMP) GetNext(oid Oid) (string, interface{}, error) {
	requestID := getRandomRequestID()
	req, err := EncodeSequence([]interface{}{Sequence, int(w.Version), w.Community,
		[]interface{}{AsnGetNextRequest, requestID, 0, 0,
			[]interface{}{Sequence,
				[]interface{}{Sequence, oid, nil}}}})
	if err != nil {
		return "", nil, err
	}

	response := make([]byte, bufSize)
	numRead, err := poll(w.conn, req, response, w.retries, w.timeout)
	if err != nil {
		return "", nil, err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		return "", nil, err
	}

	// Find the varbinds
	respPacket := decodedResponse[3].([]interface{})
	varbinds := respPacket[4].([]interface{})
	result := varbinds[1].([]interface{})

	resultOid := result[1].(string)
	resultVal := result[2]

	return resultOid, resultVal, nil
}

/* GetBulk is semantically the same as maxRepetitions getnext requests, but in a single GETBULK SNMP packet.

   Caveat: many devices will silently drop GETBULK requests for more than some number of maxrepetitions, if
   it doesn't work, try with a lower value and/or use GetTable. */
func (w WapSNMP) GetBulk(oid Oid, maxRepetitions int) (map[string]interface{}, error) {
	requestID := getRandomRequestID()
	req, err := EncodeSequence([]interface{}{Sequence, int(w.Version), w.Community,
		[]interface{}{AsnGetBulkRequest, requestID, 0, maxRepetitions,
			[]interface{}{Sequence,
				[]interface{}{Sequence, oid, nil}}}})
	if err != nil {
		return nil, err
	}

	response := make([]byte, bufSize, bufSize)
	numRead, err := poll(w.conn, req, response, w.retries, w.timeout)
	if err != nil {
		return nil, err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		return nil, err
	}

	// Find the varbinds
	respPacket := decodedResponse[3].([]interface{})
	respVarbinds := respPacket[4].([]interface{})

	result := make(map[string]interface{})
	for _, v := range respVarbinds[1:] { // First element is just a sequence
		oid := v.([]interface{})[1].(string)
		value := v.([]interface{})[2]
		result[oid] = value
	}

	return result, nil
}

// GetTable efficiently gets an entire table from an SNMP agent. Uses GETBULK requests to go fast.
func (w WapSNMP) GetTable(oid Oid) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lastOid := oid.Copy()
	for lastOid.Within(oid) {
		log.Printf("Sending GETBULK(%v, 50)\n", lastOid)
		results, err := w.GetBulk(lastOid, 50)
		if err != nil {
			return nil, fmt.Errorf("received GetBulk error => %v\n", err)
		}
		newLastOid := lastOid.Copy()
		for o, v := range results {
			oAsOid := MustParseOid(o)
			if oAsOid.Within(oid) {
				result[o] = v
			}
			newLastOid = oAsOid
		}

		if reflect.DeepEqual(lastOid, newLastOid) {
			// Not making any progress ? Assume we reached end of table.
			break
		}
		lastOid = newLastOid
	}
	return result, nil
}

// ParseTrap parses a received SNMP trap and returns  a map of oid to objects
func (w WapSNMP) ParseTrap(response []byte) error {
	decodedResponse, err := DecodeSequence(response)
	if err != nil {
		return err
	}
	var community string

	// Fetch the varbinds out of the packet.
	snmpVer := decodedResponse[1].(int)
	if snmpVer <= 1 {
		snmpVer++
	}
	fmt.Printf("Version:%d\n", snmpVer)
	if snmpVer < 3 {
		community = decodedResponse[2].(string)
		fmt.Printf("Community:%s\n", community)
	} else {
		/*
			for i, val := range decodedResponse{
				fmt.Printf("Resp:%v:type=%v\n",i,reflect.TypeOf(val));
			}
		*/
		v3HeaderStr := decodedResponse[3].(string)
		v3HeaderDecoded, err := DecodeSequence([]byte(v3HeaderStr))
		if err != nil {
			fmt.Printf("Error 2 decoding:%v\n", err)
			return err
		}

		w.engineID = v3HeaderDecoded[1].(string)
		w.engineBoots = int32(v3HeaderDecoded[2].(int))
		w.engineTime = int32(v3HeaderDecoded[3].(int))
		w.User = v3HeaderDecoded[4].(string)
		respAuthParam := v3HeaderDecoded[5].(string)
		respPrivParam := v3HeaderDecoded[6].(string)
		fmt.Printf("username=%s\n", w.User)

		if len(respAuthParam) == 0 || len(respPrivParam) == 0 {
			return errors.New("response is not encrypted")
		}
		if len(w.Trapusers) == 0 {
			return errors.New("No SNMP V3 trap user configured")
		}

		founduser := false
		for _, v3user := range w.Trapusers {
			if v3user.User == w.User {
				w.AuthAlg = v3user.AuthAlg
				w.PrivAlg = v3user.PrivAlg
				w.AuthPwd = v3user.AuthPwd
				w.PrivPwd = v3user.PrivPwd
				founduser = true
				break
			}
		}
		if !founduser {
			return errors.New("No matching user found")
		}

		//keys
		if w.AuthKey == "" {
			w.AuthKey = password_to_key(w.AuthPwd, w.engineID, w.AuthAlg)
		}

		if w.PrivKey == "" {
			privKey := password_to_key(w.PrivPwd, w.engineID, w.AuthAlg)
			w.PrivKey = string(([]byte(privKey))[0:16])
		}

		encryptedResp := decodedResponse[4].(string)
		plainResp := w.decrypt(encryptedResp, respPrivParam)

		pduDecoded, err := DecodeSequence([]byte(plainResp))
		if err != nil {
			fmt.Printf("Error 3 decoding:%v\n", err)
			return err
		}
		decodedResponse = pduDecoded
	}
	//fmt.Printf("%#v\n",decodedResponse);

	respPacket := decodedResponse[3].([]interface{})
	var varbinds []interface{}
	if snmpVer == 1 {
		fmt.Printf("OID: %s\n", respPacket[1])
		fmt.Printf("Agent Address: %s\n", respPacket[2])
		fmt.Printf("Generic Trap: %d\n", respPacket[3])
		varbinds = respPacket[6].([]interface{})
	} else {
		varbinds = respPacket[4].([]interface{})
	}

	for i := 1; i < len(varbinds); i++ {
		varoid := varbinds[i].([]interface{})[1]
		result := varbinds[i].([]interface{})[2]
		fmt.Printf("%s = %s\n", varoid, result)
	}
	fmt.Printf("\n")

	return nil
}

// Close the net.conn in WapSNMP.
func (w WapSNMP) Close() error {
	return w.conn.Close()
}
