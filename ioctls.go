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

//newGoEventFromCEvent is a helper converting the "page_fault_event_t" C struct
//from c_definitions.h to the "Event" Go struct from event.go
func newGoEventFromCEvent(cEvent *C.page_fault_event_t) *Event {
	e := &Event{
		ID:                      uint64(cEvent.id),
		FaultedGPA:              uint64(cEvent.faulted_gpa),
		ErrorCode:               uint32(cEvent.error_code),
		HaveRipInfo:             bool(cEvent.have_rip_info),
		RIP:                     uint64(cEvent.rip),
		Timestamp:               time.Unix(0, int64(cEvent.ns_timestamp)),
		HaveRetiredInstructions: bool(cEvent.have_retired_instructions),
		RetiredInstructions:     uint64(cEvent.retired_instructions),
	}
	return e
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

//CmdReadGuestMemory reads size bytes from gpa and returns them as []byte. If hostDecryption is set, the data
//is decrypted with the hosts memory encryption key before returning. If wbinvdCPU is >= 0, "wbinvd" is
//executed on that logical CPU. This is required in the SEV-ES setting.
func (a *IoctlAPI) CmdReadGuestMemory(gpa, size uint64, hostDecryption bool, wbinvdCPU int) ([]byte, error) {
	buf := make([]byte, size)
	argStruct := C.read_guest_memory_t{
		gpa:                   C.uint64_t(gpa),
		length:                C.uint64_t(size),
		decrypt_with_host_key: C.bool(hostDecryption),
		wbinvd_cpu:            C.int(wbinvdCPU),
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

		e := newGoEventFromCEvent(&resultBuf)
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

//CmdBatchTrackingStart will instruct kernel to alloc room for expectedEvents many page fault events
//that will be stored without userspace notification. The VCPU must be pinned to perfCPU because
//the retired instruction perf is used to break page tracking loops without RIP progress
//For re-tracking trackingType will be used. You still need to track the intial pages yourself, e.g.
//by calling CmdUnTrackAllPages
func (a *IoctlAPI) CmdBatchTrackingStart(trackingType PageTrackMode, expectedEvents uint64, perfCPU int) error {
	argStruct := C.batch_track_config_t{
		tracking_type:   C.int(trackingType),
		expected_events: C.uint64_t(expectedEvents),
		perf_cpu:        C.int(perfCPU),
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a.kvmFile.Fd(), C.KVM_USPT_BATCH_TRACK_START, uintptr(unsafe.Pointer(&argStruct))); errno != 0 {
		return fmt.Errorf("KVM_USPT_BATCH_TRACK_START ioctl failed with errno %v", errno)
	}
	return nil
}

func (a *IoctlAPI) CmdBatchTrackingEventCount() (uint64, error) {
	argStruct := C.batch_track_event_count_t{}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a.kvmFile.Fd(), C.KVM_USPT_BATCH_TRACK_EVENT_COUNT, uintptr(unsafe.Pointer(&argStruct))); errno != 0 {
		return 0, fmt.Errorf("KVM_USPT_BATCH_TRACK_EVENT_COUNT ioctl failed with errno %v", errno)
	}
	return uint64(argStruct.event_count), nil
}

func (a *IoctlAPI) CmdBatchTrackingStopAndGet(eventCount uint64) ([]*Event, bool, error) {

	//allocate CBytes to hold result. No Gargabe collection
	sizeofCEvent := uint64(C.sizeof_page_fault_event_t)
	sizeofCBuf := sizeofCEvent * eventCount
	cBuff := C.malloc(C.ulong(sizeofCBuf))
	defer C.free(cBuff)

	//call ioctl

	argStruct := C.batch_track_stop_and_get_t{
		out_buf:            (*C.page_fault_event_t)(cBuff),
		length:             C.uint64_t(eventCount),
		error_during_batch: C.bool(false),
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, a.kvmFile.Fd(), C.KVM_USPT_BATCH_TRACK_STOP, uintptr(unsafe.Pointer(&argStruct))); errno != 0 {
		return nil, false, fmt.Errorf("KVM_USPT_BATCH_TRACK_STOP ioctl failed with errno %v", errno)
	}

	//convert from c type to go type

	//weird hacky cast from https://stackoverflow.com/questions/48756732/what-does-1-30c-yourtype-do-exactly-in-cgo
	cBuffAsSlice := (*[1 << 30]C.page_fault_event_t)(unsafe.Pointer(cBuff))[:eventCount:eventCount]
	events := make([]*Event, eventCount)
	for i := range events {
		events[i] = newGoEventFromCEvent(&cBuffAsSlice[i])
	}

	return events, bool(argStruct.error_during_batch), nil
}
