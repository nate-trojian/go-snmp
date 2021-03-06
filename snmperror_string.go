// Code generated by "stringer -type=SNMPError"; DO NOT EDIT.

package wapsnmp

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[NoError-0]
	_ = x[TooBig-1]
	_ = x[NoSuchName-2]
	_ = x[BadValue-3]
	_ = x[ReadOnly-4]
	_ = x[GenErr-5]
	_ = x[NoAccess-6]
	_ = x[WrongType-7]
	_ = x[WrongLength-8]
	_ = x[WrongEncoding-9]
	_ = x[WrongValue-10]
	_ = x[NoCreation-11]
	_ = x[InconsistentValue-12]
	_ = x[ResourceUnavailable-13]
	_ = x[CommitFailed-14]
	_ = x[UndoFailed-15]
	_ = x[AuthorizationError-16]
	_ = x[NotWritable-17]
	_ = x[InconsistentName-18]
}

const _SNMPError_name = "NoErrorTooBigNoSuchNameBadValueReadOnlyGenErrNoAccessWrongTypeWrongLengthWrongEncodingWrongValueNoCreationInconsistentValueResourceUnavailableCommitFailedUndoFailedAuthorizationErrorNotWritableInconsistentName"

var _SNMPError_index = [...]uint8{0, 7, 13, 23, 31, 39, 45, 53, 62, 73, 86, 96, 106, 123, 142, 154, 164, 182, 193, 209}

func (i SNMPError) String() string {
	if i >= SNMPError(len(_SNMPError_index)-1) {
		return "SNMPError(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _SNMPError_name[_SNMPError_index[i]:_SNMPError_index[i+1]]
}
