// Code generated by "stringer -type=SNMPError"; DO NOT EDIT.

package wapsnmp

import "strconv"

const _SNMPError_name = "NoErrorTooBigNoSuchNameBadValueReadOnlyGenErrNoAccessWrongTypeWrongLengthWrongEncodingWrongValueNoCreationInconsistentValueResourceUnavailableCommitFailedUndoFailedAuthorizationErrorNotWritableInconsistentName"

var _SNMPError_index = [...]uint8{0, 7, 13, 23, 31, 39, 45, 53, 62, 73, 86, 96, 106, 123, 142, 154, 164, 182, 193, 209}

func (i SNMPError) String() string {
	if i >= SNMPError(len(_SNMPError_index)-1) {
		return "SNMPError(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _SNMPError_name[_SNMPError_index[i]:_SNMPError_index[i+1]]
}
