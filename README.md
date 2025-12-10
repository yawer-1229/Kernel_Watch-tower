# Kernel Watchtower: eBPF Based Rootkit Detection Engine

![Language](https://img.shields.io/badge/Language-C%20%7C%20Python-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20Kernel%20Ring%200-green)
![Tech](https://img.shields.io/badge/Tech-eBPF%20%7C%20BCC-orange)
![Security](https://img.shields.io/badge/Focus-Rootkit%20Detection-red)

**Kernel Watchtower** is a real-time security observability tool built using **eBPF (Extended Berkeley Packet Filter)**. It hooks directly into the Linux Kernel to intercept malicious system calls as they happen, bypassing standard user space logging.

## System In Action

### 1. Engine Startup
The Python agent loads the C based eBPF bytecode into the kernel and attaches probes to `sys_execve`, `sys_openat`, and `sys_unlinkat`.
![Startup](assets/01_startup.png)

---

## Detection Capabilities

### 2. Heuristic Analysis (Behavioral Detection)
The engine detects anomalies based on behavior, not just signatures.
* **RED:** Malware execution (`./bpfdoor`).
* **YELLOW:** Sensitive file access (Reading `/etc/passwd` & `/etc/shadow`).
* **PURPLE:** Evasion attempts (Deleting logs via `rm my.log`).

![Behavioral Test](assets/02_behavioral_test.png)

---

## Defense in Depth Validation (The Diamorphine Test)

I validated the tool against **Diamorphine**, a real world Loadable Kernel Module (LKM) rootkit.

**The Attack:**
The attacker compiles the rootkit and attempts to inject it into the kernel using `insmod`.
![Attacker View](assets/03_attacker_view.png)

**The Detection:**
The Kernel Watchtower intercepts the `insmod` syscall immediately. It triggers a Critical alert before the kernel even processes the module. Note how the sensor catches the attempt even though the Hardened Linux Kernel eventually blocked the module (Defense in Depth).
![Rootkit Alert](assets/04_rootkit_alert.png)

## Tech Stack
* **Core:** C (Kernel Space), Python (User Space)
* **Framework:** BCC (BPF Compiler Collection)
* **Infrastructure:** Google Cloud Platform (GCP)