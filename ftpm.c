//#include "vmlinux.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/ptrace.h>
#include <stdbool.h>

#define MAX_BUF_LEN         128
#define MAX_PATH            64
#define MAX_OPENTAT_ENTRIES 32
#define MAX_FAULT_ENTRIES   256
#define FAULT_RANDOM        0x1
#define FAULT_ACTIVE        0x2
#define FAULT_DEACTIVE      0x3

struct event {
    __u32 cmd;
};

struct iovec {
    void *iov_base;	        /* Pointer to data.  */
    unsigned int iov_len;	/* Length of data.  */
};

struct tpm_connection_fd {
    int fd;                 /* for socket, just an int */
};

struct tpm_msg {
    __u8 raw[MAX_BUF_LEN];
    __u64 size;
};

struct tpm_req_header {
    __u16 tag;
    __u32 size;
    __u32 cmd;
} __attribute__((packed));

struct tpm_resp_header {
    __u16 tag;
    __u32 size;
    __u32 errcode;
} __attribute__((packed));

struct fault_table {
    __u32 cmd;
    __u32 errcode;
    __u32 type;
};

struct swtpm_io_read_args {
    int connection_fd;
    unsigned char *buffer;
    __u32 *bufferLength;
    __u32 bufferSize;
};

struct target_data {
    __u32 pid;
    __u32 log_mode;
    char comm[MAX_PATH];
    char devpath[MAX_PATH];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(value, struct event);
} events SEC(".maps");

struct bpf_map_def SEC("maps") openat2_tracker = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(char),
    .max_entries = MAX_OPENTAT_ENTRIES,
};

struct bpf_map_def SEC("maps") tpm_fd_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = MAX_OPENTAT_ENTRIES,
};

struct bpf_map_def SEC("maps") target_swtpm_io_read = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(struct swtpm_io_read_args),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") fualt_table_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct fault_table),
    .max_entries = MAX_FAULT_ENTRIES,
};

struct bpf_map_def SEC("maps") target_data_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct target_data),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") target_fault = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct fault_table),
    .max_entries = MAX_FAULT_ENTRIES,
};

static __inline int is_target_pid(__u32 pid) {
    __u32 key = 0;
    struct target_data *td = bpf_map_lookup_elem(&target_data_map, &key);
    if (!td || td->pid != pid) {
        return -1;
    }
    return 0;
}

static __inline int is_log_mode() {
    __u32 key = 0;
    struct target_data *td = bpf_map_lookup_elem(&target_data_map, &key);
    if (!td || !td->log_mode) {
        return -1;
    }
    return 0;
}

static __inline int isNull(const char *str) {
    char c = *str;
    return c == '\0';
}

static __inline int bpf_strncmp(const char *s1, const char *s2, __u32 n) {
    for (__u32 i = 0; i < n; i++) {
        char c1, c2;
        c1 = s1[i];
        c2 = s2[i];
        if (c1 != c2) {
            return c1 - c2;
        }
        if (c1 == '\0') {
            break;
        }
    }

    return 0;
}

SEC("kprobe/do_sys_openat2")
int kprobe_do_sys_openat2(struct pt_regs *regs) {
    char comm[MAX_PATH] = {};
    char fname[MAX_PATH] = {};
    const char *filename = (const char *)PT_REGS_PARM2(regs);
    if (!filename) {
        return 0;
    }

    if (bpf_get_current_comm(&comm, MAX_PATH) < 0) {
        return 0;
    }
    if (bpf_probe_read_user_str(fname, MAX_PATH, filename) < 0) {
        return 0;
    }

    // get the target data from user-space
    __u32 key = 0;
    struct target_data *td = bpf_map_lookup_elem(&target_data_map, &key);
    if (!td) {
        bpf_printk("[!] do_sys_openat2 - failed to find target data\n");
        return 0;
    }

    // check if current openat2 args match with the target data
    if (bpf_strncmp(td->devpath, fname, MAX_PATH) != 0) {
        return 0;
    }
    if (!isNull(td->comm)) {
        if (bpf_strncmp(td->comm, comm, MAX_PATH) != 0) {
            return 0;
        }
    }

    // save the pid of the target process for later filtering
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    td->pid = pid;
    if (bpf_map_update_elem(&target_data_map, &key, td, BPF_ANY < 0)){
        bpf_printk("[!] do_sys_openat2 - failed to store pid=%d\n", pid);
        return 0;
    }

    // save the pid_tgid to track the openat2 ret probe and get the fd
    char val = 0;
    if (bpf_map_update_elem(&openat2_tracker, &pid_tgid, &val, BPF_ANY < 0)){
        bpf_printk("[!] do_sys_openat2 - failed to store pid_tgid=%d\n", pid_tgid);
        return 0;
    }

    bpf_printk("[+] do_sys_openat2 - target=\"%s\", dev=\"%s\"\n", td->comm, td->devpath);
    return 0;
}

SEC("kretprobe/do_sys_openat2")
int kretprobe_do_sys_openat2(struct pt_regs *regs) {
    // if we are not tracking this openat2 call, do nothing
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (bpf_map_lookup_elem(&openat2_tracker, &pid_tgid) == NULL) {
        return 0;
    }

    // save the fd for later filtering
    int fd = PT_REGS_RC(regs);
    if (fd < 0) {
        return 0;
    }
    if (bpf_map_update_elem(&tpm_fd_map, &fd, &fd, BPF_ANY) < 0) {
        bpf_printk("[!] do_sys_openat2 - failed to store fd=%d\n", fd);
    }

    return 0;
}

SEC("fentry/ksys_write")
int BPF_PROG(ksys_write, int fd, char *user_buf, unsigned int count, int ret) {
    // check this is the target process
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_target_pid(pid) < 0) {
        return 0;
    }

    // check if this is the target fd
    if (bpf_map_lookup_elem(&tpm_fd_map, &fd) == NULL) {
        return 0;
    }

    struct tpm_msg tmsg = {};
    tmsg.size = count;
    if (tmsg.size < sizeof(struct tpm_req_header)) {
        bpf_printk("[!] ksys_write - buffer is too small\n");
        return 0;
    }
    if (tmsg.size > MAX_BUF_LEN) {
       tmsg.size = MAX_BUF_LEN;
    }
    if (bpf_probe_read(&tmsg.raw, tmsg.size, user_buf) < 0) {
        bpf_printk("[!] ksys_write - failed to read buffer\n");
        return 0;
    }

    // get req_header, convert fields to little-endian
    struct tpm_req_header *req_header = (struct tpm_req_header *)tmsg.raw;
    req_header->tag = __builtin_bswap16(req_header->tag);
    req_header->size = __builtin_bswap32(req_header->size);
    req_header->cmd = __builtin_bswap32(req_header->cmd);

    // see if we are interested in this command
    __u32 key = req_header->cmd;
    struct fault_table *ftable = bpf_map_lookup_elem(&fualt_table_map, &key);
    if (!ftable) {
        return 0;
    }

    // if fault is not active do nothing
    if (ftable->type == FAULT_DEACTIVE) {
        return 0;
    }

    // if random, flip a coin and decide we should inject the fault or not
    if (ftable->type == FAULT_RANDOM) {
        if (bpf_get_prandom_u32() % 2 == 0) {
            return 0;
        }
    }

    // store the fault data with tag as the key, read uses this to track cmd
    struct fault_table fdata = {
        .cmd = req_header->cmd,
        .errcode = ftable->errcode,
        .type = ftable->type,
    };
    key = req_header->tag;
    if ( bpf_map_update_elem(&target_fault, &key, &fdata, BPF_NOEXIST) < 0) {
        bpf_printk("[!] ksys_write - failed to store fault data with key=0x%llx\n",key);
        return 0;
    }

    bpf_printk("[+] ksys_write - stored for fault injection key=x%llx tag=0x%llx cmd=0x%llx\n", 
        key, req_header->tag, req_header->cmd);
    return 0;
}

SEC("fexit/ksys_read")
int BPF_PROG(ksys_read, int fd, const char *buf, unsigned int count, int ret) {
    // check this is the target process
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32; 
    if (is_target_pid(pid) < 0) {
        return 0;
    }

    // check if this is the target fd
    if (bpf_map_lookup_elem(&tpm_fd_map, &fd) == NULL) {
        return 0;
    }

    struct tpm_msg tmsg = {};
    tmsg.size = count;
    if (tmsg.size < sizeof(struct tpm_resp_header)) {
        bpf_printk("[!] ksys_read - error buffer is too small\n");
        return 0;
    }
    if (tmsg.size > MAX_BUF_LEN) {
        tmsg.size = MAX_BUF_LEN;
    }

    char resp_buf[MAX_BUF_LEN];
    if (bpf_probe_read(tmsg.raw, tmsg.size, buf) < 0) {
        bpf_printk("[!] ksys_read - failed to read buffer\n");
        return 0;
    }

    // copy the req_header, convert fields to little-endian and store the event
    struct tpm_resp_header *resp_header = (struct tpm_resp_header *)tmsg.raw;
    resp_header->tag = __builtin_bswap16(resp_header->tag);
    resp_header->size = __builtin_bswap32(resp_header->size);
    resp_header->errcode = __builtin_bswap32(resp_header->errcode);

    // check if we have a fault to inject
    __u32 key = resp_header->tag;
    struct fault_table *fdata = bpf_map_lookup_elem(&target_fault, &key);
    if (!fdata) {
        return 0;
    }

    // check if it is still active or not
    key = fdata->cmd;
    struct fault_table *ftable = bpf_map_lookup_elem(&fualt_table_map, &key);
    if (!ftable) {
        return 0;
    }

    // do nothing if not active
    if (ftable->type == FAULT_DEACTIVE) {
        return 0;
    }

    // inject the fault
    unsigned int errcode = __builtin_bswap32(fdata->errcode);
    if (bpf_probe_write_user(&((struct tpm_resp_header *)buf)->errcode, &errcode, sizeof(errcode)) < 0) {
        bpf_printk("[!] ksys_read - failed to inject fault\n");
        return 0;
    }

    // delete the fault data once it is injected, if we want more fault it should
    // be placed again from read syscall.
    key = resp_header->tag;
    if (bpf_map_delete_elem(&target_fault, &key) < 0) {
        bpf_printk("[!] ksys_read - failed to delete fault data with key=0x%llx\n", key);
    }
    
    bpf_printk("[+] ksys_read - fault injected tag=0x%llx errcode=0x%llx cmd=0x%llx\n", 
        resp_header->tag, fdata->errcode, fdata->cmd);

    return 0;
}

SEC("uprobe/SWTPM_IO_Read")
int uprobe_SWTPM_IO_Read(struct pt_regs *regs) {
    // tgid is what user-space calls PID, tpid is what user-space calls TID
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct tpm_connection_fd *connection_fd = (struct tpm_connection_fd *)PT_REGS_PARM1(regs);
    unsigned char *buffer = ( unsigned char *)PT_REGS_PARM2(regs);
    __u32 *bufferLength = (__u32 *)PT_REGS_PARM3(regs);
    __u32 bufferSize = PT_REGS_PARM4(regs);
    if (!connection_fd || !buffer || !bufferLength) {
        bpf_printk("[!] uprobe_SWTPM_IO_Read - invalid args\n");
        return 0;
    }

    // read the connection_fd
    struct tpm_connection_fd conn_fd;
    if (bpf_probe_read_user(&conn_fd, sizeof(struct tpm_connection_fd), connection_fd) < 0) {
        bpf_printk("[!] uprobe_SWTPM_IO_Read - failed to read connection_fd\n");
        return 0;
    }
    if (conn_fd.fd < 0) {
        bpf_printk("[!] uprobe_SWTPM_IO_Read - invalid connection_fd\n");
        return 0;
    }

    // store the args with the tid as the key
    struct swtpm_io_read_args args = {
        .connection_fd = conn_fd.fd,
        .buffer = buffer,
        .bufferLength = bufferLength,
        .bufferSize = bufferSize,
    };
    if (bpf_map_update_elem(&target_swtpm_io_read, &pid_tgid, &args, BPF_ANY) < 0) {
        bpf_printk("[!] uprobe_SWTPM_IO_Read - failed to store args with key=0x%llx\n", pid_tgid);
    }

    return 0;
}

SEC("uretprobe/SWTPM_IO_Read")
int uretprobe_SWTPM_IO_Read(struct pt_regs *regs) {
    // look up the args with the tid as the key
    __u64 pid_tgid = bpf_get_current_pid_tgid(); 
    struct swtpm_io_read_args *args = bpf_map_lookup_elem(&target_swtpm_io_read, &pid_tgid);
    if (!args) {
        bpf_printk("[!] uretprobe_SWTPM_IO_Read - failed to find args with key=0x%llx\n", pid_tgid);
        return 0;
    }

    // don't proceed if the connection is not open
    if (args->connection_fd < 0) {
        bpf_printk("[!] uretprobe_SWTPM_IO_Read - invalid connection_fd\n");
        return 0;
    }

    // read the size max size of data
    __u32 max_size = 0;
    if (bpf_probe_read_user(&max_size, sizeof(__u32), args->bufferLength) < 0) {
        bpf_printk("[!] uretprobe_SWTPM_IO_Read - failed to read bufferLength\n");
        return 0;
    }
    if (max_size == 0 || max_size < sizeof(struct tpm_req_header)) {
        bpf_printk("[!] uretprobe_SWTPM_IO_Read - invalid bufferLength=%lld\n", max_size);
        return 0;
    }
    if (max_size > MAX_BUF_LEN) {
        max_size = MAX_BUF_LEN;
    }

    // read the req buffer
    unsigned char buf[MAX_BUF_LEN];
    if (bpf_probe_read_user(&buf, max_size, args->buffer) < 0) {
        bpf_printk("[!] uretprobe_SWTPM_IO_Read - failed to read buffer\n");
        return 0;
    }

    // get the req_header
    struct tpm_req_header *req_header = (struct tpm_req_header *)buf;
    req_header->tag = __builtin_bswap16(req_header->tag);
    req_header->size = __builtin_bswap32(req_header->size);
    req_header->cmd = __builtin_bswap32(req_header->cmd);

    // if we are in log mode, just log and return
    if (is_log_mode() >= 0) {
        struct event ev = {
            .cmd = req_header->cmd
        };
        bpf_perf_event_output(regs, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
        return 0;
    }

    // see if we are interested in this command
    __u32 key = req_header->cmd;
    struct fault_table *ftable = bpf_map_lookup_elem(&fualt_table_map, &key);
    if (!ftable) {
        return 0;
    }

    // if fault is not active do nothing
    if (ftable->type == FAULT_DEACTIVE) {
        return 0;
    }

    // if random, flip a coin and decide we should inject the fault or not
    if (ftable->type == FAULT_RANDOM) {
        if (bpf_get_prandom_u32() % 2 == 0) {
            return 0;
        }
    }
    
    // store the fault data with tag as the key
    struct fault_table fdata = {
        .cmd = req_header->cmd,
        .errcode = ftable->errcode,
        .type = ftable->type,
    };
    key = req_header->tag;
    bpf_map_update_elem(&target_fault, &key, &fdata, BPF_NOEXIST);
    bpf_printk("[+] uretprobe_SWTPM_IO_Read - stored for fault injection key=%d tag=0x%llx cmd=0x%llx\n", 
        key, req_header->tag, req_header->cmd);

    return 0;
}

SEC("uprobe/SWTPM_IO_Write")
int uprobe_SWTPM_IO_Write(struct pt_regs *regs) {
    struct tpm_connection_fd *connection_fd = (struct tpm_connection_fd *)PT_REGS_PARM1(regs);
    struct iovec *iovec = (struct iovec *)PT_REGS_PARM2(regs);
    int iovcnt = (int)PT_REGS_PARM3(regs);
    if (!connection_fd || !iovec || iovcnt < 1) {
        bpf_printk("[!] uprobe_SWTPM_IO_Write - invalid args\n");
        return 0;
    }

    // if we are in log mode, just return
    if (is_log_mode() >= 0) {
        return 0;
    }

    // read the connection_fd
    struct tpm_connection_fd conn_fd;
    if (bpf_probe_read_user(&conn_fd, sizeof(struct tpm_connection_fd), connection_fd) < 0) {
        bpf_printk("[!] uprobe_SWTPM_IO_Read - failed to read connection_fd\n");
        return 0;
    }

    // don't proceed if the connection is not open
    if (conn_fd.fd < 0) {
        bpf_printk("[!] uprobe_SWTPM_IO_Write - connection not open\n");
        return 0;
    }

    // swtpm uses at most 3 iovec, first one is prefix (contains size of the data),
    // second one is the actual data and the third one is the ack (0 size and base).
    if (iovcnt > 3)
        iovcnt = 3;

    // read the response iovec
    struct iovec iov;
    if (bpf_probe_read_user(&iov, sizeof(struct iovec), &iovec[1]) < 0) {
        bpf_printk("[!] uprobe_SWTPM_IO_Write - failed to read iovec\n");
        return 0;
    }
    if (!iov.iov_base) {
        bpf_printk("[!] uprobe_SWTPM_IO_Write - invalid iov_base\n");
        return 0;
    }

     __u32 max_size = iov.iov_len;
    if (max_size < sizeof(struct tpm_resp_header)) {
        bpf_printk("[!] uprobe_SWTPM_IO_Write - response buffer too small, size=%lld\n", max_size);
        return 0;
    }
    if (max_size > MAX_BUF_LEN) {
        max_size = MAX_BUF_LEN;
    }

    // read the first response buffer
    unsigned char buf[MAX_BUF_LEN];
    if (bpf_probe_read_user(&buf, max_size, iov.iov_base) < 0) {
        bpf_printk("[!] uprobe_SWTPM_IO_Write - failed to read response buffer\n");
        return 0;
    }

    // get the resp_header
    struct tpm_resp_header *resp_header = (struct tpm_resp_header *)buf;
    resp_header->tag = __builtin_bswap16(resp_header->tag);
    resp_header->size = __builtin_bswap32(resp_header->size);
    resp_header->errcode = __builtin_bswap32(resp_header->errcode);
  
    // check if we have a fault to inject
    __u32 key = resp_header->tag;
    struct fault_table *fdata = bpf_map_lookup_elem(&target_fault, &key);
    if (!fdata) {
        return 0;
    }

    // check if it is still active or not
    key = fdata->cmd;
    struct fault_table *ftable = bpf_map_lookup_elem(&fualt_table_map, &key);
    if (!ftable) {
        return 0;
    }

    // do nothing if not active
    if (ftable->type == FAULT_DEACTIVE) {
        return 0;
    }

    // inject the fault
    unsigned int errcode = __builtin_bswap32(fdata->errcode);
    if (bpf_probe_write_user(&((struct tpm_resp_header *)iov.iov_base)->errcode, &errcode, sizeof(errcode)) < 0) {
        bpf_printk("[!] uprobe_SWTPM_IO_Write - failed to inject fault\n");
        return 0;
    }

    // delete the fault data once it is injected, if we want more fault it should
    // be placed again from read syscall.
    key = resp_header->tag;
    if (bpf_map_delete_elem(&target_fault, &key) < 0) {
        bpf_printk("[!] uprobe_SWTPM_IO_Write - failed to delete fault data with key=0x%llx\n", key);
    }
    
    bpf_printk("[+] uprobe_SWTPM_IO_Write - fault injected tag=0x%llx errcode=0x%llx cmd=0x%llx\n", 
        resp_header->tag, fdata->errcode, fdata->cmd);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
