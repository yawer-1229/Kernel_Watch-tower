#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct data_t {
    u32 pid;
    u32 uid;
    u32 type; 
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(events);


static void submit_event(struct pt_regs *ctx, char *filename, u32 type) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.type = type;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user(&data.filename, sizeof(data.filename), filename);
    events.perf_submit(ctx, &data, sizeof(data));
}

// HOOK 1: Executing Programs (Malware Detection)
int syscall__execve(struct pt_regs *ctx, const char __user *filename) {
    submit_event(ctx, (char *)filename, 1);
    return 0;
}

// HOOK 2: Opening Files (Detecting /etc/shadow access)
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename) {
    submit_event(ctx, (char *)filename, 2);
    return 0;
}

// HOOK 3: Deleting Files (Detecting Log wiping)
int syscall__unlinkat(struct pt_regs *ctx, int dfd, const char __user *filename) {
    submit_event(ctx, (char *)filename, 3);
    return 0;
}