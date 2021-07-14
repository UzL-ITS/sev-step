package sevStep

import (
	"fmt"
	"strings"
)

type PfErrorBit uint32

//Uses PFERR_*** defintions from Linux at arch/x86/include/asm/kvm_host.h line 205 ff
const (
	PfErrorPresent = PfErrorBit(uint32(0x1) << 0)
	PfErrorWrite   = PfErrorBit(uint32(0x1) << 1)
	PfErrorUser    = PfErrorBit(uint32(0x1) << 2)
	PfErrorRSVD    = PfErrorBit(uint32(0x1) << 3)
	PfErrorFetch   = PfErrorBit(uint32(0x1) << 4)
	PfErrorPK      = PfErrorBit(uint32(0x1) << 5)
)

var allPfErrors = []PfErrorBit{PfErrorPresent, PfErrorWrite, PfErrorUser, PfErrorRSVD, PfErrorFetch, PfErrorPK}

func (p PfErrorBit) String() string {
	switch p {
	case PfErrorPresent:
		return "Present"
	case PfErrorWrite:
		return "Write"
	case PfErrorUser:
		return "User"
	case PfErrorRSVD:
		return "RSVD"
	case PfErrorFetch:
		return "Fetch"
	case PfErrorPK:
		return "PK"
	default:
		return "Unknown"
	}
}

//ArePfErrorsSet returns true if all bits are set
func ArePfErrorsSet(errorCode uint32, bits ...PfErrorBit) bool {
	for _, v := range bits {
		if errorCode&uint32(v) == 0 {
			return false
		}
	}
	return true
}

//ErrorCodeToString returns a string with the names of the errors bits set in code
func ErrorCodeToString(code uint32) (string, error) {
	buf := strings.Builder{}
	for _, v := range allPfErrors {
		if ArePfErrorsSet(code, v) {
			if _, err := buf.WriteString(v.String() + " "); err != nil {
				return "", fmt.Errorf("allocation error : err")
			}
		}
	}
	return buf.String(), nil
}
