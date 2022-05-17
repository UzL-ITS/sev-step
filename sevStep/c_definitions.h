#ifndef MY_KVM_IOCTLS
#define MY_KVM_IOCTLS

#include <stdint.h>
#include <stdbool.h>
#include <sys/ioctl.h>


typedef struct {
    //Internal ID associated with this event. Required to acknowledge the event
    uint64_t id;
    //GPA where teh fault occurred
    uint64_t faulted_gpa;
    //Error Code of the page fault, see Linux Kernel arch/x86/include/asm/kvm_host.h line 205 ff for definitions
    uint32_t error_code;
    //If true, the rip field contains valid data.
	bool have_rip_info;
	//If have_rip_info is true, this contains the instruction pointer where the VM occurred.
	//Getting the rip is only tried when specified in the initial KVM_USPT_REGISTER_PID call (see restrictions there)
	uint64_t rip;
	//Time at which the event happened
	uint64_t ns_timestamp;
	//If true, retired_instructions contains valid data
	bool have_retired_instructions;
	//If have_retired_instructions is true, this field contains the retired instructions count of the attacked VM.
	//Needs to be configured with KVM_USPT_SETUP_RETINSTR_PERF
	uint64_t retired_instructions;
} page_fault_event_t;


typedef struct {
    //This specifies which events cause a page fault. See enum kvm_page_track_mode in the kernel patch
	//for allowed values
	int tracking_type;
	//Instruct kernel to alloc room for expectedEvents many page fault events
	uint64_t expected_events;
	//Logical cpu to read the retired instructions performance counter on. The VM's vCPU must be pinned to the same core
	int perf_cpu;
	//If re-track is set the initial tracking_type will be re-applied to faulted pages. You still need to track the intial pages yourself, e.g.
    //by calling KVM_USPT_TRACK_ALL
    //This only works to a certain extend:
    // 1) Like described for KVM_TRACK_PAGE, you cannot track back to back accesses to the same page
    // 2) There are certain situations where multiple pages need to be accessible at the same time, for the VM to make progress (see https://stackoverflow.com/questions/60968748/do-x86-instructions-require-their-own-encoding-as-well-as-all-of-their-arguments).
    // We try to detect this, by not re-tracking a page, when there where zero retired instructions since the last fault.
	bool retrack;
} batch_track_config_t;

typedef struct {
    //Filled with number of events that where tracked so far
	uint64_t event_count;
} batch_track_event_count_t;

typedef struct {
    //Caller allocated buffer that can hold up to length events
	page_fault_event_t* out_buf;
	//Number of events to get. Can be queried with KVM_USPT_BATCH_TRACK_EVENT_COUNT
	uint64_t length;
	//If true, there was an error during batch tracking. See dmesg log for more information
	bool error_during_batch;
} batch_track_stop_and_get_t;

typedef struct {
    //Logical cpu on which we want to read the counter
	int cpu;
	//R esult param
	uint64_t retired_instruction_count;
} retired_instr_perf_t;

typedef struct {
    //The performance counter for retired instructions is per cpu.
    //This is the logical cpu to program the counter on. To bu useful, the VM
    //must be pinned to the some logical cpu. This can e.g. be done using
    //https://github.com/zegelin/qemu-affinity
	int cpu;
} retired_instr_perf_config_t;


typedef struct {
    //pid of the userspace application calling the ioctl
    int pid;
    //if set to true, the API will try to get the instruction pointer of the VM at which an event occurs.
    //This only works for plain VMs or SEV VMs in debug mode. Production SEV VM hide this information
	bool get_rip;
} userspace_ctx_t;



typedef struct {
    //Internal ID of the event to acknowledge, as specified in the page_fault_event_t
    uint64_t id;
} ack_event_t;


typedef struct {
    //GPA which should be tracked
	uint64_t gpa;
	//This specifies which events cause a page fault. See enum kvm_page_track_mode in the kernel patch
	//for allowed values
	int track_mode;
} track_page_param_t;

typedef struct {
    //Guest physical address that should be read
	uint64_t gpa;
	//Amount of bytes to read, starting from gpa
	uint64_t length;
	//SEV specific. If UNSET, you will get ciphertext of the VM memory. If SET, the ciphertext will be decrypted using the HV's
	//key. Note that this will not give you the plaintext seen by the VM unless this is a shared page (as the VM uses a different memory encryption key)
	bool decrypt_with_host_key;
	//Controls flushing. Flushing is required for SEV, to get the most recent memory entries, as there is no coherency with the VM's
	//memory accesses.
	//If wbinvdCPU is >= 0, "wbinvd" is
    //executed on that logical CPU. This is required in the SEV-ES setting.
	int wbinvd_cpu;
	//Caller allocated buffer to store the read data
	void* output_buffer;
}read_guest_memory_t;

typedef struct {
    //this specifies which events cause a page fault. See enum kvm_page_track_mode in the kernel patch
    //for allowed values
	int track_mode;
} track_all_pages_t;

#define KVMIO 0xAE

#define KVM_USPT_POLL_EVENT_NO_EVENT 1000
#define KVM_USPT_POLL_EVENT_GOT_EVENT 0

#define KVM_GET_API_VERSION _IO(KVMIO, 0x00)


//Track accesses to a page, as specified in track_page_param_t
//Only triggers once. To track the next access to this page we need to call this again
//Note that if you issue to track the access to a page while handling the previous
//page track event for that same page, you end up in an endless loop as you remove the access
//rights from the page table before the VM got a change to do the access. Thus you cannot track two back to back
//accesses to the same page.
#define KVM_TRACK_PAGE _IOWR(KVMIO, 0x20, track_page_param_t)

//Constructor, intializes the api for use. Must be called before any other api commands
#define KVM_USPT_REGISTER_PID _IOWR(KVMIO, 0x21, userspace_ctx_t)

#define KVM_USPT_WAIT_AND_SEND _IO(KVMIO, 0x22) //deprecated

//Check if there is a new (pagefault) event. If the kernel side encounters an event
//it will block execution until the userspace part has acknowledged the event using
// KVM_USPT_ACK_EVENT.
//This command is intended to be called in a poll loop.
//If the ioctls return code is KVM_USPT_POLL_EVENT_NO_EVENT, there was not event
//If the ioctls return code is KVM_USPT_POLL_EVENT_GOT_EVENT, there is a new event
//and the provided, caller allocated page_fault_event_t struct is filled.
//All other return values indicate an error.
#define KVM_USPT_POLL_EVENT _IOWR(KVMIO, 0x23, page_fault_event_t)

//If the kernel side encounters an event it will block execution until the
// userspace part has acknowledged the event using this call
#define KVM_USPT_ACK_EVENT _IOWR(KVMIO, 0x24, ack_event_t)

//Read VM memory, see comments in arg struct for more details
#define KVM_READ_GUEST_MEMORY _IOWR(KVMIO, 0x25, read_guest_memory_t)

//Destructor, stops all page tracking and resets internal states. Should be called when done using the api
#define KVM_USPT_RESET _IO(KVMIO, 0x26)

//Similar to KVM_TRACK_PAGE but for all pages of the VM. Like for KVM_TRACK_PAGE, only the first
//access to the page triggers an event
#define KVM_USPT_TRACK_ALL _IOWR(KVMIO, 0x27, track_all_pages_t)

//Allow the VM to access all of it pages, to stop further events
#define KVM_USPT_UNTRACK_ALL _IOWR(KVMIO, 0x28, track_all_pages_t)

//Initialize retired instructions performance counter
#define KVM_USPT_SETUP_RETINSTR_PERF _IOWR(KVMIO, 0x30,retired_instr_perf_config_t)

//Read the retired instructions performance counter. Must be initialized with KVM_USPT_SETUP_RETINSTR_PERF first
#define KVM_USPT_READ_RETINSTR_PERF _IOWR(KVMIO,0x31, retired_instr_perf_t)

//The batch track API is intended to track page faults without waiting for acknowledgement for each event
//This is much faster, but lacks the interactivity.

//Initialize batch tracking. You still need to configure the which accesses should cause events using
//KVM_USPT_TRACK_ALL or KVM_TRACK_PAGE. If configured in batch_track_config_t, the pages will be re-tracked
//automtically ( see restrictions in batch_track_config_t comments)
#define KVM_USPT_BATCH_TRACK_START _IOWR(KVMIO,0x32,batch_track_config_t)

//Stop tracking and get results. Inside the arg struct, you need to specify the number of events to get.
//This can be obtained by calling KVM_USPT_BATCH_TRACK_EVENT_COUNT first.
#define KVM_USPT_BATCH_TRACK_STOP _IOWR(KVMIO,0x33,batch_track_stop_and_get_t)

//Get the number of events tracked so far.
#define KVM_USPT_BATCH_TRACK_EVENT_COUNT _IOWR(KVMIO,0x34,batch_track_event_count_t)

#endif // MY_KVM_IOCTLS
