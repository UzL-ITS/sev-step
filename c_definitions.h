#ifndef MY_KVM_IOCTLS
#define MY_KVM_IOCTLS

#include<stdint.h>
#include <stdbool.h>
#include <sys/ioctl.h>

typedef struct {
	int cpu; //cpu on which we want to read the counter
	uint64_t retired_instruction_count; //result param
} retired_instr_perf_t;

typedef struct {
	int cpu; //cpu on which counter should be programmed
} retired_instr_perf_config_t;

typedef struct dbg_decrypt_param {
	uint64_t src_gpa;
} dbg_decrypt_param_t;

typedef struct lookup_table {
	uint64_t start_gpa;
	uint64_t bytes;
} lookup_table_t;

typedef struct memaccess_instr {
	uint64_t gpa; //position of the instruction in memory
	uint64_t lookup_table_index; //index to lookup_tables so that we know which one is accessed by this instruction
} memaccess_instr_t;

typedef struct sev_step_param {
	uint64_t start_gpa; //point at which we want to start stepping
	uint64_t stop_gpa; //point at which we want to stop stepping
	//
	uint32_t tmict_value; //timeout for apic timer
	uint64_t steps; //how many instructions we want to step (zerosteps do not count into this)
	//
	lookup_table_t * lookup_tables; //array of lookup_tables
	uint64_t lookup_tables_len; //size of lookup_tables array
	//
	memaccess_instr_t * lookup_accesses; //array of memaccess_instr
	uint64_t lookup_accesses_len;
	//
	int callback_nr; //select between different callback functions performing the actual interpretation of the stepping data

} sev_step_param_t;


enum scan_direction {
    SD_SINGLE,  //only probe single offset specified in direction_helper
	SD_FORWARD, //all offsests forward
	SD_REVERSE, //all offsets reverse
	SD_RANDOM, //randomized; direction_helper constains the "SEQ_WINDOW" size (1 means no sequential accesses)
};

typedef struct {
	bool do_flush;
	uint64_t target_gpa;
	enum scan_direction direction;
	uint64_t direction_helper;
	bool do_vmpage_flush;
	uint64_t perf_events[6];
	uint64_t perf_uint_mask[6];

} cpuid_wait_param_t;

typedef struct {
    int pid;
	bool get_rip;
} userspace_ctx_t;

typedef struct {
    uint64_t id; //filled automatically
    uint64_t faulted_gpa;
    uint32_t error_code;
	bool have_rip_info;
	uint64_t rip;
	uint64_t ns_timestamp;

} page_fault_event_t;

typedef struct {
    uint64_t id;
} ack_event_t;


typedef struct {
	uint64_t gpa;
	int track_mode;
} track_page_param_t;

typedef struct {
	uint64_t gpa;
	uint64_t length;
	bool decrypt_with_host_key;
	void* output_buffer;
}read_guest_memory_t;

typedef struct {
	int track_mode;
} track_all_pages_t;

#define SIG_TEST 44
#define KVMIO 0xAE

#define KVM_USPT_POLL_EVENT_NO_EVENT 1000
#define KVM_USPT_POLL_EVENT_GOT_EVENT 0

#define KVM_GET_API_VERSION _IO(KVMIO, 0x00)
#define KVM_CPUID_WAIT _IOWR(KVMIO, 0x15, cpuid_wait_param_t)
#define KVM_DBG_DEC _IOWR(KVMIO, 0x16, dbg_decrypt_param_t)
#define KVM_SEV_STEP _IOWR(KVMIO, 0x17, sev_step_param_t)
#define KVM_STOP_CNT _IO(KVMIO, 0x18)
#define KVM_TRACK_PAGE _IOWR(KVMIO, 0x20, track_page_param_t) //done
#define KVM_USPT_REGISTER_PID _IOWR(KVMIO, 0x21, userspace_ctx_t) //done
#define KVM_USPT_WAIT_AND_SEND _IO(KVMIO, 0x22) //deprecated
#define KVM_USPT_POLL_EVENT _IOWR(KVMIO, 0x23, page_fault_event_t) //done
#define KVM_USPT_ACK_EVENT _IOWR(KVMIO, 0x24, ack_event_t) //done
#define KVM_READ_GUEST_MEMORY _IOWR(KVMIO, 0x25, read_guest_memory_t) //done
#define KVM_USPT_RESET _IO(KVMIO, 0x26) //done
#define KVM_USPT_TRACK_ALL _IOWR(KVMIO, 0x27, track_all_pages_t)
#define KVM_USPT_UNTRACK_ALL _IOWR(KVMIO, 0x28, track_all_pages_t)
#define KVM_USPT_SETUP_RETINSTR_PERF _IOWR(KVMIO, 0x30,retired_instr_perf_config_t)
#define KVM_USPT_READ_RETINSTR_PERF _IOWR(KVMIO,0x31, retired_instr_perf_t)

#endif // MY_KVM_IOCTLS
