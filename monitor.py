
from bcc import BPF


print("Loading Kernel Watchtower V3 (Rootkit Hunter Mode)...")
b = BPF(src_file="detector.c")

# Attach hooks to system calls
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__openat")
b.attach_kprobe(event=b.get_syscall_fnname("unlinkat"), fn_name="syscall__unlinkat")

print("Engine Running. Waiting for Diamorphine or malicious activity...")


def print_event(cpu, data, size):
    event = b["events"].event(data)
    try:
        command = event.comm.decode('utf-8', 'replace')
        filename = event.filename.decode('utf-8', 'replace')
    except:
        return

   

    # SPECIAL: DETECT KERNEL MODULE LOADING (Diamorphine)
    if "insmod" in command or "modprobe" in command:
        print(f"\033[41m[CRITICAL][ROOTKIT] KERNEL MODULE LOAD ATTEMPT: PID={event.pid} COMM={command} FILE={filename}\033[0m")
        return 

    # TYPE 1: EXECUTION (Malware binaries)
    if event.type == 1:
        if "diamorphine" in filename or "bpfdoor" in filename or "rootkit" in filename:
             print(f"\033[41m[CRITICAL][EXEC] KNOWN ROOTKIT SIGNATURE: PID={event.pid} FILE={filename}\033[0m")

    # TYPE 2: SENSITIVE FILE ACCESS 
    elif event.type == 2:
        if "shadow" in filename or "passwd" in filename:
            print(f"\033[93m[WARN][ACCESS] SENSITIVE FILE TOUCHED: PID={event.pid} COMM={command} FILE={filename}\033[0m")

    # TYPE 3: DELETION 
    elif event.type == 3:
        if "log" in filename or "history" in filename:
            print(f"\033[95m[ALERT][EVASION] LOG DELETION ATTEMPT: PID={event.pid} COMM={command} FILE={filename}\033[0m")


b["events"].open_perf_buffer(print_event)
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    exit()