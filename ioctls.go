//Package sevStep Wraps the sev-step ioctl api
package sevStep

//This file contains the actual ioctl wrappers, using the definitions in "c_definitions.h"

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"
)

//#include "./c_definitions.h"
//#include <stdlib.h>
import "C"

type PageTrackMode int

const (
	PageTrackWrite = PageTrackMode(iota)
	PageTrackAccess
	PageTrackResetAccess
	PageTrackExec
	PageTraceResetExec
)

type IoctlAPI struct {
	kvmFile *os.File
}

//NewIoctlAPI opens kvm file and registers application. Must be Closed once done
func NewIoctlAPI(kvmFilePath string) (*IoctlAPI, error) {
	f, err := os.OpenFile(kvmFilePath, syscall.O_RDWR|syscall.O_CREAT, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open device file : %v", err)
	}
	res := &IoctlAPI{kvmFile: f}
	err = res.register()
	if err != nil {
		return nil, fmt.Errorf("register failed : %v", err)
	}
	return res, nil
}

//Close underlying ioctl file. Will also call CmdReset
func (a *IoctlAPI) Close() error {
	if err := a.CmdReset(); err != nil {
		log.Printf("CmdReset failed before Close : %v", err)
	}
	return a.kvmFile.Close()
}

func (a *IoctlAPI) register() error {
	registerStruct := C.userspace_ctx_t{pid: C.int(os.Getpid())}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a.kvmFile.Fd(), C.KVM_USPT_REGISTER_PID, uintptr(unsafe.Pointer(&registerStruct))); errno != 0 {
		return fmt.Errorf("REGISTER_PID ioctl failed with errno %v", errno)
	}
	return nil
}

func (a *IoctlAPI) CmdReset() error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a.kvmFile.Fd(), C.KVM_USPT_RESET, uintptr(0)); errno != 0 {
		return fmt.Errorf("KVM_USPT_RESET ioctl failed with errno %v", errno)
	}
	return nil
}

func (a *IoctlAPI) CmdReadGuestMemory(gpa, size uint64, hostDecryption bool) ([]byte, error) {
	buf := make([]byte, size)
	argStruct := C.read_guest_memory_t{
		gpa:                   C.uint64_t(gpa),
		length:                C.uint64_t(size),
		decrypt_with_host_key: C.bool(hostDecryption),
		output_buffer:         C.CBytes(buf),
	}

	defer C.free(argStruct.output_buffer)

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a.kvmFile.Fd(), C.KVM_READ_GUEST_MEMORY, uintptr(unsafe.Pointer(&argStruct))); errno != 0 {
		return nil, fmt.Errorf("KVM_READ_GUEST_MEMORY ioctl failed with errno %v", errno)
	}

	return C.GoBytes(argStruct.output_buffer, C.int(size)), nil
}

func (a *IoctlAPI) CmdAckEvent(id uint64) error {
	argStruct := C.ack_event_t{
		id: C.uint64_t(id),
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a.kvmFile.Fd(), C.KVM_USPT_ACK_EVENT, uintptr(unsafe.Pointer(&argStruct))); errno != 0 {
		return fmt.Errorf("KVM_USPT_ACK_EVENT ioctl failed with errno %v", errno)
	}

	return nil
}

//CmdPollEvent returns new event if available. There are two negative outcomes: if error != nil something went wrong,
//if error == nil but the bool return value is false, the ioctl was fine but there is no new event
func (a *IoctlAPI) CmdPollEvent() (*Event, bool, error) {
	resultBuf := C.page_fault_event_t{}

	code, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a.kvmFile.Fd(), C.KVM_USPT_POLL_EVENT, uintptr(unsafe.Pointer(&resultBuf)))
	if errno != 0 {
		return nil, false, fmt.Errorf("KVM_USPT_ACK_EVENT ioctl failed with errno %v", errno)
	}
	//special return value for no event is no error
	switch code {
	case C.KVM_USPT_POLL_EVENT_NO_EVENT:
		return nil, false, nil
	case C.KVM_USPT_POLL_EVENT_GOT_EVENT:
		e := &Event{
			ID:          uint64(resultBuf.id),
			FaultedGPA:  uint64(resultBuf.faulted_gpa),
			ErrorCode:   uint32(resultBuf.error_code),
			HaveRipInfo: bool(resultBuf.have_rip_info),
			RIP:         uint64(resultBuf.rip),
		}
		return e, true, nil
	default:
		return nil, false, fmt.Errorf("KVM_USPT_ACK_EVENT ioctl failed with errno %v", errno)

	}
}

func (a *IoctlAPI) CmdTrackPage(gpa uint64, trackMode PageTrackMode) error {
	argStruct := C.track_page_param_t{
		gpa:        C.uint64_t(gpa),
		track_mode: C.int(trackMode),
	}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a.kvmFile.Fd(), C.KVM_TRACK_PAGE, uintptr(unsafe.Pointer(&argStruct))); errno != 0 {
		return fmt.Errorf("KVM_USPT_ACK_EVENT ioctl failed with errno %v", errno)
	}
	return nil
}
