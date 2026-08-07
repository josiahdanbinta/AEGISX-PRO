"""
AEGIS - Falco-Style Kernel & Container Detection Rules (Tier 4)
Syscall-level detection rules for host and container security monitoring.
Implements Falco-compatible rule format for kernel events, file integrity,
and container runtime security.
"""
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Rule Definitions (Falco-style YAML â†’ runtime evaluation)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

FALCO_RULES = {
    # â”€â”€ Container Runtime â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    "container_privileged_started": {
        "rule": "Privileged Container Started",
        "desc": "Detect containers started with --privileged flag",
        "condition": "container_started and container_privileged",
        "output": "Privileged container started (name=%container.name, image=%container.image)",
        "priority": "WARNING",
        "tags": ["container", "privileged", "misconfiguration"],
        "mitre": ["T1610"],
        "syscall_patterns": ["clone", "setns"],
        "kernel_fields": {"container.privileged": True},
    },
    "container_sensitive_mount": {
        "rule": "Sensitive Mount Detected",
        "desc": "Container mounting sensitive host directories",
        "condition": "container_started and sensitivemount",
        "output": "Sensitive mount (%container.mount) detected in container %container.name",
        "priority": "CRITICAL",
        "tags": ["container", "mount", "escape"],
        "mitre": ["T1611"],
        "syscall_patterns": ["mount"],
        "sensitive_paths": [
            "/proc", "/sys", "/etc", "/root", "/var/run/docker.sock",
            "/var/run/crio/crio.sock", "/var/run/containerd/containerd.sock",
        ],
    },
    "container_docker_socket_mount": {
        "rule": "Docker Socket Mounted",
        "desc": "Container mounting the Docker socket - potential breakout",
        "condition": "container_started and docker_socket_mount",
        "output": "Docker socket mounted in container %container.name",
        "priority": "CRITICAL",
        "tags": ["container", "docker", "escape", "privilege_escalation"],
        "mitre": ["T1610", "T1611"],
        "paths": ["/var/run/docker.sock"],
    },
    "container_unexpected_process": {
        "rule": "Unexpected Process in Container",
        "desc": "Process spawned unexpectedly inside a container",
        "condition": "container_spawn_process and unexpected_binary",
        "output": "Unexpected process %proc.name (%proc.cmdline) in container %container.name",
        "priority": "WARNING",
        "tags": ["container", "process", "anomaly"],
        "mitre": ["T1059"],
        "syscall_patterns": ["execve", "execveat"],
        "suspicious_binaries": ["nmap", "tcpdump", "masscan", "hydra", "john", "hashcat",
                                  "chisel", "ngrok", "frp", "socat"],
    },
    "container_write_below_binary_dir": {
        "rule": "Write Below Binary Directory",
        "desc": "Executable file creation below /bin, /sbin, /usr/bin etc.",
        "condition": "create_executable and below_binary_dir",
        "output": "Executable created below binary dir by %proc.name (%user.name)",
        "priority": "CRITICAL",
        "tags": ["container", "filesystem", "malware", "persistence"],
        "mitre": ["T1543", "T1059"],
        "syscall_patterns": ["openat", "creat", "write", "chmod"],
        "binary_dirs": ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"],
    },

    # â”€â”€ File Integrity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    "file_integrity_binary_modified": {
        "rule": "System Binary Modified",
        "desc": "Critical system binary files modified - possible rootkit or backdoor",
        "condition": "modify_system_binary",
        "output": "System binary %fd.name modified by %proc.name (user=%user.name)",
        "priority": "CRITICAL",
        "tags": ["filesystem", "binary", "rootkit", "backdoor"],
        "mitre": ["T1014", "T1554"],
        "syscall_patterns": ["openat", "write", "rename", "link", "unlink"],
        "protected_paths": [
            "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
            "/lib/", "/lib64/", "/boot/", "/etc/passwd", "/etc/shadow",
            "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/crontab",
        ],
    },
    "file_integrity_crontab_modified": {
        "rule": "Crontab Modified",
        "desc": "Scheduled task configuration changed",
        "condition": "modify_crontab and not cron_update",
        "output": "Crontab modified by %proc.name (user=%user.name, cmd=%proc.cmdline)",
        "priority": "HIGH",
        "tags": ["filesystem", "cron", "persistence"],
        "mitre": ["T1053"],
        "syscall_patterns": ["openat", "write", "rename"],
        "paths": ["/etc/crontab", "/var/spool/cron/", "/etc/cron.d/", "/etc/cron.hourly/",
                  "/etc/cron.daily/", "/etc/cron.weekly/", "/etc/cron.monthly/"],
    },
    "file_integrity_ssh_authorized_keys": {
        "rule": "SSH Authorized Keys Modified",
        "desc": "SSH authorized_keys file modified - potential backdoor",
        "condition": "modify_authorized_keys",
        "output": "SSH authorized_keys modified for user %user.name from %proc.name",
        "priority": "HIGH",
        "tags": ["filesystem", "ssh", "persistence", "backdoor"],
        "mitre": ["T1098"],
        "paths": ["authorized_keys", ".ssh/authorized_keys"],
    },
    "file_integrity_ld_preload": {
        "rule": "LD_PRELOAD Hijack",
        "desc": "Modification of ld.so.preload or LD_PRELOAD environment",
        "condition": "modify_ld_preload",
        "output": "ld.so.preload modified by %proc.name - potential library injection",
        "priority": "CRITICAL",
        "tags": ["filesystem", "ld_preload", "hijack", "rootkit"],
        "mitre": ["T1574"],
        "paths": ["/etc/ld.so.preload", "/etc/ld.so.conf.d/"],
    },

    # â”€â”€ Process / Execution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    "process_reverse_shell": {
        "rule": "Reverse Shell Detected",
        "desc": "Process spawning a shell with redirected stdin/stdout to a socket",
        "condition": "spawned_process and shell_redirected_to_network",
        "output": "Reverse shell from %proc.name (%proc.cmdline) to %fd.sip:%fd.sport",
        "priority": "CRITICAL",
        "tags": ["process", "shell", "reverse_shell", "c2"],
        "mitre": ["T1059", "T1071"],
        "shell_commands": ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "cmd.exe",
                            "powershell.exe", "nc", "ncat", "netcat"],
        "redirect_patterns": [r">/dev/tcp/", r">/dev/udp/", r"bash\s+-i\s+>&"],
    },
    "process_network_tool_download": {
        "rule": "Network Tool Downloaded",
        "desc": "Download of common post-exploitation tools",
        "condition": "spawned_process and network_tool_executed",
        "output": "Network tool %proc.name executed by user %user.name",
        "priority": "HIGH",
        "tags": ["process", "network", "tool", "c2"],
        "mitre": ["T1105"],
        "tool_names": ["nmap", "masscan", "zmap", "rustscan", "naabu",
                        "chisel", "ngrok", "frp", "socat", "ligolo"],
    },
    "process_base64_encoded_execution": {
        "rule": "Base64 Encoded Command",
        "desc": "Command execution with base64-encoded arguments",
        "condition": "spawned_process and base64_encoded_arg",
        "output": "Base64 encoded command: %proc.cmdline",
        "priority": "HIGH",
        "tags": ["process", "obfuscation", "base64"],
        "mitre": ["T1027", "T1059"],
        "base64_patterns": [r"-e\s+[A-Za-z0-9+/=]{20,}", r"-enc\s+[A-Za-z0-9+/=]{20,}",
                             r"base64\s+-d", r"FromBase64String"],
    },
    "process_disable_defense": {
        "rule": "Defense Evasion - Disable Security Tools",
        "desc": "Attempt to stop or disable security tools/AV/firewall",
        "condition": "spawned_process and disable_defense_tool",
        "output": "Defense evasion: %proc.cmdline by user %user.name",
        "priority": "CRITICAL",
        "tags": ["process", "defense_evasion", "tamper"],
        "mitre": ["T1562"],
        "disable_patterns": [
            "systemctl stop", "service stop", "sc stop", "sc config.*disabled",
            "Stop-Service", "Set-Service.*-StartupType Disabled",
            "netsh advfirewall.*state off", "ufw disable",
            "Set-MpPreference -DisableRealtimeMonitoring",
            "chkconfig.*off", "update-rc.d.*disable",
        ],
    },
    "process_wget_curl_pipe_bash": {
        "rule": "Curl/Wget Pipe to Shell",
        "desc": "Download and execute pattern via curl/wget piped to shell",
        "condition": "spawned_process and download_pipe_to_shell",
        "output": "Download-to-shell: %proc.cmdline",
        "priority": "CRITICAL",
        "tags": ["process", "download", "execute", "c2"],
        "mitre": ["T1059", "T1105"],
        "download_patterns": [r"curl\s+.*\|\s*(ba)?sh", r"wget\s+.*-O\s*-\s*\|\s*(ba)?sh",
                               r"curl\s+.*\|\s*python", r"curl\s+.*\|\s*perl"],
    },

    # â”€â”€ Network Activity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    "network_outbound_to_unusual_port": {
        "rule": "Outbound Connection to Unusual Port",
        "desc": "Process connecting outbound to non-standard port",
        "condition": "outbound_network and unusual_port",
        "output": "%proc.name connecting to %fd.rip:%fd.rport (unusual port)",
        "priority": "MEDIUM",
        "tags": ["network", "outbound", "c2", "anomaly"],
        "mitre": ["T1071"],
        "standard_ports": {80, 443, 22, 53, 8080, 8443, 123, 25, 587, 993, 143, 3306, 5432, 6379},
    },
    "network_dns_query_to_suspicious_tld": {
        "rule": "DNS Query to Suspicious TLD",
        "desc": "Resolve domains with suspicious top-level domains",
        "condition": "dns_query and suspicious_tld",
        "output": "DNS query to %fd.name (suspicious TLD) from %proc.name",
        "priority": "MEDIUM",
        "tags": ["network", "dns", "c2", "anomaly"],
        "mitre": ["T1071"],
        "suspicious_tlds": {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
                             ".cc", ".su", ".ws", ".work", ".date", ".racing", ".stream"},
    },
    "network_unexpected_incoming": {
        "rule": "Unexpected Incoming Connection",
        "desc": "Process receiving connection from external IP without known service",
        "condition": "incoming_network and not known_service",
        "output": "Unexpected incoming connection to %proc.name from %fd.rip",
        "priority": "WARNING",
        "tags": ["network", "inbound", "listener", "c2"],
        "mitre": ["T1571"],
    },

    # â”€â”€ Kernel Events â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    "kernel_module_load": {
        "rule": "Kernel Module Loaded",
        "desc": "New kernel module loaded - check for rootkits",
        "condition": "kernel_module_loaded and not whitelisted_module",
        "output": "Kernel module %fd.name loaded (initiated by %proc.name)",
        "priority": "WARNING",
        "tags": ["kernel", "module", "rootkit"],
        "mitre": ["T1014"],
        "syscall_patterns": ["init_module", "finit_module"],
        "whitelist": [],
    },
    "kernel_ptrace_attach": {
        "rule": "ptrace Attach to Process",
        "desc": "Process using ptrace to attach to another (debugging/code injection)",
        "condition": "ptrace_attach and not debugger_process",
        "output": "ptrace attach from %proc.name (pid=%proc.pid) to target %proc.tpid",
        "priority": "WARNING",
        "tags": ["kernel", "ptrace", "code_injection", "credential_dumping"],
        "mitre": ["T1055", "T1003"],
        "syscall_patterns": ["ptrace"],
    },
    "kernel_bpf_program_load": {
        "rule": "eBPF Program Loaded",
        "desc": "New eBPF program loaded into kernel",
        "condition": "bpf_program_loaded",
        "output": "eBPF program loaded by %proc.name (type=%fd.type)",
        "priority": "MEDIUM",
        "tags": ["kernel", "ebpf", "anomaly"],
        "mitre": ["T1055"],
        "syscall_patterns": ["bpf"],
    },

    # â”€â”€ Credential Access â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    "credential_dump_procdump": {
        "rule": "Process Memory Dump (LSASS)",
        "desc": "Attempt to dump process memory (potential credential theft)",
        "condition": "spawned_process and process_dump_lsass",
        "output": "Credential dump attempt: %proc.cmdline targeting LSASS",
        "priority": "CRITICAL",
        "tags": ["process", "credential_dumping", "lsass"],
        "mitre": ["T1003"],
        "dump_patterns": ["procdump.*lsass", "rundll32.*comsvcs.*MiniDump",
                           "mimikatz", "sekurlsa", "Invoke-Mimikatz", "Out-Minidump"],
    },
}


class FalcoRuleEngine:
    """Evaluates Falco-style rules against kernel events and process data."""

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        triggered = []
        event_str = json.dumps(event).lower()
        proc_name = (event.get("proc", {}).get("name") or event.get("process_name") or
                      event.get("process", {}).get("name") or "").lower()
        cmdline = (event.get("proc", {}).get("cmdline") or event.get("cmdline") or
                    event.get("command_line") or "").lower()
        fd_name = (event.get("fd", {}).get("name") or event.get("filename") or
                    event.get("path") or "").lower()
        user = (event.get("user", {}).get("name") or event.get("username") or "").lower()

        for rule_id, rule in FALCO_RULES.items():
            match = False
            confidence = 0.5

            if rule.get("syscall_patterns"):
                syscall = event.get("syscall") or event.get("syscall_type") or ""
                if any(p in str(syscall).lower() for p in rule["syscall_patterns"]):
                    match = True
                    confidence = 0.7

            if rule.get("kernel_fields"):
                for k, v in rule["kernel_fields"].items():
                    if event.get(k) == v or event_str.find(f'"{k}": {str(v).lower()}') >= 0:
                        match = True
                        confidence = 0.85

            if rule.get("sensitive_paths") or rule.get("paths"):
                paths = rule.get("sensitive_paths", []) + rule.get("paths", [])
                if any(p.lower() in (fd_name or event_str) for p in paths):
                    match = True
                    confidence = 0.9

            if rule.get("suspicious_binaries"):
                if any(b in (proc_name or cmdline or event_str) for b in rule["suspicious_binaries"]):
                    match = True
                    confidence = 0.8

            if rule.get("tool_names"):
                if any(t in (proc_name or cmdline) for t in rule["tool_names"]):
                    match = True
                    confidence = 0.75

            if rule.get("shell_commands"):
                if any(s.lower() in (proc_name or cmdline) for s in rule["shell_commands"]):
                    match = True
                    confidence = 0.7

            if rule.get("disable_patterns") or rule.get("dump_patterns"):
                patterns = rule.get("disable_patterns", []) + rule.get("dump_patterns", [])
                if any(re.search(p, cmdline or event_str, re.IGNORECASE) for p in patterns):
                    match = True
                    confidence = 0.95

            if rule.get("download_patterns") or rule.get("redirect_patterns"):
                patterns = rule.get("download_patterns", []) + rule.get("redirect_patterns", [])
                if any(re.search(p, cmdline or event_str) for p in patterns):
                    match = True
                    confidence = 0.95

            if rule.get("base64_patterns"):
                if any(re.search(p, cmdline or event_str) for p in rule["base64_patterns"]):
                    match = True
                    confidence = 0.85

            if rule.get("protected_paths"):
                if any(p.lower() in fd_name for p in rule["protected_paths"]):
                    match = True
                    confidence = 0.9

            if rule.get("binary_dirs"):
                if event.get("is_executable") and any(d in fd_name for d in rule["binary_dirs"]):
                    match = True
                    confidence = 0.85

            if rule.get("suspicious_tlds"):
                domain = event.get("dns", {}).get("name") or event.get("domain") or fd_name
                if any(domain.endswith(tld) for tld in rule["suspicious_tlds"]):
                    match = True
                    confidence = 0.6

            if rule.get("standard_ports"):
                port = event.get("fd", {}).get("rport") or event.get("destination_port")
                if port and int(port) not in rule["standard_ports"]:
                    match = True
                    confidence = 0.4

            if match:
                triggered.append({
                    "rule_id": rule_id,
                    "rule_name": rule["rule"],
                    "description": rule["desc"],
                    "priority": rule["priority"],
                    "confidence": confidence,
                    "output": rule["output"].replace("%proc.name", proc_name or "unknown")
                                       .replace("%proc.cmdline", cmdline[:200] or "unknown")
                                       .replace("%proc.pid", str(event.get("proc", {}).get("pid", "")))
                                       .replace("%fd.name", fd_name[:200] or "unknown")
                                       .replace("%fd.rip", str(event.get("fd", {}).get("rip", "")))
                                       .replace("%fd.rport", str(event.get("fd", {}).get("rport", "")))
                                       .replace("%fd.sip", str(event.get("fd", {}).get("sip", "")))
                                       .replace("%fd.sport", str(event.get("fd", {}).get("sport", "")))
                                       .replace("%fd.type", str(event.get("fd", {}).get("type", "")))
                                       .replace("%user.name", user or "unknown")
                                       .replace("%container.name", str(event.get("container", {}).get("name", "")))
                                       .replace("%container.image", str(event.get("container", {}).get("image", "")))
                                       .replace("%container.mount", fd_name[:100] or "unknown"),
                    "tags": rule.get("tags", []),
                    "mitre_techniques": rule.get("mitre", []),
                    "raw_event": event,
                })

        return triggered

    def evaluate_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        all_triggers = []
        for event in events:
            triggers = self.evaluate_event(event)
            all_triggers.extend(triggers)
        return all_triggers

    def get_all_rules(self) -> List[Dict[str, Any]]:
        return [
            {"id": rid, "name": r["rule"], "priority": r["priority"],
             "tags": r.get("tags", []), "mitre": r.get("mitre", []),
             "description": r["desc"]}
            for rid, r in FALCO_RULES.items()
        ]

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        r = FALCO_RULES.get(rule_id)
        if r:
            return {"id": rule_id, "name": r["rule"], "priority": r["priority"],
                    "tags": r.get("tags", []), "mitre": r.get("mitre", []),
                    "description": r["desc"], "condition": r.get("condition"),
                    "output": r.get("output"), "syscall_patterns": r.get("syscall_patterns")}
        return None


falco_engine = FalcoRuleEngine()
