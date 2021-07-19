//Package sevStep Wraps the sev-step ioctl api
package sevStep

//This file contains the actual ioctl wrappers, using the definitions in "c_definitions.h"

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"time"
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
	//If tryGetRIP is set the kernel
	//side will enrich page fault events with their RIP. This only works for plain VMs or
	//SEV-ES VMs with debug bit set in policy. However, for the latter getting the rip
	//is still relatively expensive
	tryGetRIP bool
}

//NewIoctlAPI opens kvm file and registers application. If tryGetRIP is set the kernel
//side will enrich page fault events with their RIP. This only works for plain VMs or
//SEV-ES VMs with debug bit set in policy. However, for the latter getting the rip
//is still relatively expensive
//IoctlAPI must be Closed once done
func NewIoctlAPI(kvmFilePath string, tryGetRIP bool) (*IoctlAPI, error) {
	f, err := os.OpenFile(kvmFilePath, syscall.O_RDWR|syscall.O_CREAT, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open device file : %v", err)
	}
	res := &IoctlAPI{
		kvmFile:   f,
		tryGetRIP: tryGetRIP,
	}
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
	registerStruct := C.userspace_ctx_t{
		pid:     C.int(os.Getpid()),
		get_rip: C.bool(a.tryGetRIP),
	}
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
			Timestamp:   time.Unix(0, int64(resultBuf.ns_timestamp)),
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

func (a *IoctlAPI) CmdTrackAllPages(trackMode PageTrackMode) error {
	argStruct := C.track_all_pages_t{
		track_mode: C.int(trackMode),
	}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a.kvmFile.Fd(), C.KVM_USPT_TRACK_ALL, uintptr(unsafe.Pointer(&argStruct))); errno != 0 {
		return fmt.Errorf("KVM_USPT_TRACK_ALL ioctl failed with errno %v", errno)
	}

	return nil
}

func (a *IoctlAPI) CmdUnTrackAllPages(trackMode PageTrackMode) error {
	argStruct := C.track_all_pages_t{
		track_mode: C.int(trackMode),
	}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a.kvmFile.Fd(), C.KVM_USPT_UNTRACK_ALL, uintptr(unsafe.Pointer(&argStruct))); errno != 0 {
		return fmt.Errorf("KVM_USPT_UNTRACK_ALL ioctl failed with errno %v", errno)
	}

	return nil
}

//CmdSetupRetInstrPerf initializes the "Retired Instruction in SVM Guest" Performance counter on
//logical the given logical cpu
func (a *IoctlAPI) CmdSetupRetInstrPerf(cpu int) error {
	argStruct := C.retired_instr_perf_config_t{
		cpu: C.int(cpu),
	}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a.kvmFile.Fd(), C.KVM_USPT_SETUP_RETINSTR_PERF, uintptr(unsafe.Pointer(&argStruct))); errno != 0 {
		return fmt.Errorf("KVM_USPT_SETUP_RETINSTR_PERF ioctl failed with errno %v", errno)

	}
	return nil
}

func (a *IoctlAPI) CmdReadRetInstrPerf(cpu int) (uint64, error) {
	argStruct := C.retired_instr_perf_t{
		cpu: C.int(cpu),
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a.kvmFile.Fd(), C.KVM_USPT_READ_RETINSTR_PERF, uintptr(unsafe.Pointer(&argStruct))); errno != 0 {
		return 0, fmt.Errorf("KVM_USPT_READ_RETINSTR_PERF ioctl failed with errno %v", errno)
	}
	retiredInstructions := uint64(argStruct.retired_instruction_count)

	return retiredInstructions, nil
}
