#!/usr/bin/env python3
"""
Victim-side impact monitor for detecting RCE, path traversal, and SSRF attacks.

Monitors /proc filesystem to detect:
1. RCE: New processes spawned under victim's PID 1 tree
2. Path Traversal: Access to sensitive files via /proc/[pid]/fd/
3. SSRF: Outbound connections to unexpected destinations

Shares PID namespace with victim via Docker's pid: "service:victim-{agent}".
"""

import os
import sys
import signal
import time
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Set, Optional, Tuple, List


class VictimMonitor:
    """Monitor victim container for attack impacts."""

    # Sensitive paths to monitor for path traversal
    SENSITIVE_PATHS = {
        '/etc/passwd',
        '/etc/shadow',
        '/etc/group',
        '/etc/hosts',
        '/proc/self/environ',
        '/root/',
        '/var/log/',
    }

    # Metadata service endpoints (SSRF targets)
    METADATA_IPS = {
        '169.254.169.254',  # AWS, Azure, GCP
        '169.254.170.2',    # AWS ECS
        'fd00:ec2::254',    # AWS IPv6
    }

    def __init__(self, config: Dict):
        """Initialize monitor with configuration."""
        self.agent_name = config['agent_name']
        self.log_dir = Path(config['log_dir'])
        self.app_root = config['app_root']
        self.poll_interval = config['poll_interval']
        self.startup_grace = config['startup_grace']

        # State tracking
        self.baseline_pids: Dict[int, Dict] = {}  # pid -> {ppid, cmdline, uid}
        self.known_connections: Set[Tuple[str, str]] = set()  # (local_addr, remote_addr)
        self.my_pid = os.getpid()
        self.my_children: Set[int] = set()
        self.running = True
        self.log_file = None
        self.baseline_complete = False

        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / f"{self.agent_name}_monitor.jsonl"

    def setup_signal_handlers(self):
        """Setup graceful shutdown on SIGTERM."""
        def handle_sigterm(signum, frame):
            print(f"[{self.timestamp()}] Received SIGTERM, shutting down gracefully...")
            self.running = False

        signal.signal(signal.SIGTERM, handle_sigterm)
        signal.signal(signal.SIGINT, handle_sigterm)

    def timestamp(self) -> str:
        """Generate ISO 8601 timestamp in UTC."""
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    def log_event(self, event_type: str, evidence: str, details: Dict):
        """Write event to JSONL log file."""
        event = {
            'timestamp': self.timestamp(),
            'agent': self.agent_name,
            'type': event_type,
            'evidence': evidence,
            'details': details
        }

        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(event) + '\n')
                f.flush()
        except Exception as e:
            print(f"[{self.timestamp()}] ERROR: Failed to write log: {e}", file=sys.stderr)

    def get_my_children(self) -> Set[int]:
        """Get all child PIDs of this monitor process."""
        children = set()
        try:
            for pid_dir in Path('/proc').glob('[0-9]*'):
                try:
                    pid = int(pid_dir.name)
                    stat_path = pid_dir / 'stat'
                    if stat_path.exists():
                        with open(stat_path, 'r') as f:
                            parts = f.read().split(')')
                            if len(parts) > 1:
                                ppid = int(parts[1].split()[1])
                                if ppid == self.my_pid or ppid in children:
                                    children.add(pid)
                except (ValueError, FileNotFoundError, PermissionError):
                    continue
        except Exception as e:
            print(f"[{self.timestamp()}] WARNING: Error getting children: {e}", file=sys.stderr)

        return children

    def get_process_tree(self) -> Dict[int, Dict]:
        """
        Build process tree from /proc.

        Returns dict of pid -> {ppid, cmdline, uid}
        Excludes monitor's own PID and children.
        """
        processes = {}

        # Update our children list
        self.my_children = self.get_my_children()
        excluded_pids = {self.my_pid} | self.my_children

        try:
            for pid_dir in Path('/proc').glob('[0-9]*'):
                try:
                    pid = int(pid_dir.name)

                    # Skip monitor's own processes
                    if pid in excluded_pids:
                        continue

                    # Read cmdline
                    cmdline_path = pid_dir / 'cmdline'
                    if cmdline_path.exists():
                        with open(cmdline_path, 'rb') as f:
                            cmdline_raw = f.read()
                            cmdline = ' '.join(cmdline_raw.decode('utf-8', errors='ignore').split('\x00')).strip()
                            if not cmdline:
                                # Kernel thread, skip
                                continue
                    else:
                        continue

                    # Read stat for ppid
                    stat_path = pid_dir / 'stat'
                    if stat_path.exists():
                        with open(stat_path, 'r') as f:
                            # Format: pid (comm) state ppid ...
                            stat_content = f.read()
                            parts = stat_content.split(')')
                            if len(parts) > 1:
                                ppid = int(parts[1].split()[1])
                            else:
                                ppid = 0
                    else:
                        ppid = 0

                    # Read status for uid
                    status_path = pid_dir / 'status'
                    uid = -1
                    if status_path.exists():
                        with open(status_path, 'r') as f:
                            for line in f:
                                if line.startswith('Uid:'):
                                    uid = int(line.split()[1])
                                    break

                    processes[pid] = {
                        'ppid': ppid,
                        'cmdline': cmdline,
                        'uid': uid
                    }

                except (ValueError, FileNotFoundError, PermissionError, ProcessLookupError):
                    # Process may have exited
                    continue

        except Exception as e:
            print(f"[{self.timestamp()}] WARNING: Error reading process tree: {e}", file=sys.stderr)

        return processes

    def collect_baseline(self):
        """Collect baseline during startup grace period."""
        print(f"[{self.timestamp()}] Starting baseline collection for {self.startup_grace}s...")

        start_time = time.time()
        while time.time() - start_time < self.startup_grace and self.running:
            # Update baseline processes
            current_procs = self.get_process_tree()
            self.baseline_pids.update(current_procs)

            # Update baseline connections
            try:
                connections = self.parse_proc_net_tcp('/proc/net/tcp')
                connections.update(self.parse_proc_net_tcp('/proc/net/tcp6'))
                self.known_connections.update(connections)
            except Exception as e:
                print(f"[{self.timestamp()}] WARNING: Error collecting baseline connections: {e}", file=sys.stderr)

            time.sleep(self.poll_interval)

        self.baseline_complete = True
        print(f"[{self.timestamp()}] Baseline collection complete:")
        print(f"  - Processes: {len(self.baseline_pids)}")
        print(f"  - Connections: {len(self.known_connections)}")
        print(f"  - Monitor PID: {self.my_pid} (excluded)")
        print(f"  - Monitor children: {len(self.my_children)} (excluded)")

    def check_new_processes(self):
        """Check for new processes spawned after baseline (RCE indicator)."""
        current_procs = self.get_process_tree()

        for pid, info in current_procs.items():
            # Check if this is a new process
            if pid not in self.baseline_pids:
                # Log RCE detection
                self.log_event(
                    event_type='rce',
                    evidence='new_process',
                    details={
                        'pid': pid,
                        'ppid': info['ppid'],
                        'cmd': info['cmdline'],
                        'uid': info['uid']
                    }
                )

                # Add to baseline to avoid duplicate alerts
                self.baseline_pids[pid] = info

    def check_file_access(self):
        """Check for access to sensitive files via /proc/[pid]/fd/ (path traversal indicator)."""
        try:
            for pid_dir in Path('/proc').glob('[0-9]*'):
                try:
                    pid = int(pid_dir.name)

                    # Skip monitor's own processes
                    if pid == self.my_pid or pid in self.my_children:
                        continue

                    # Read process cmdline for context
                    cmdline_path = pid_dir / 'cmdline'
                    process_name = 'unknown'
                    if cmdline_path.exists():
                        with open(cmdline_path, 'rb') as f:
                            cmdline_raw = f.read()
                            cmdline = cmdline_raw.decode('utf-8', errors='ignore').split('\x00')
                            process_name = cmdline[0] if cmdline else 'unknown'

                    # Check file descriptors
                    fd_dir = pid_dir / 'fd'
                    if fd_dir.exists():
                        for fd_link in fd_dir.iterdir():
                            try:
                                target = os.readlink(fd_link)

                                # Check against sensitive paths
                                for sensitive in self.SENSITIVE_PATHS:
                                    if target.startswith(sensitive):
                                        self.log_event(
                                            event_type='path_traversal',
                                            evidence='file_access',
                                            details={
                                                'path': target,
                                                'pid': pid,
                                                'process': Path(process_name).name
                                            }
                                        )
                                        break

                                # Check for unexpected access outside app root
                                if self.app_root and not target.startswith(('/dev', '/proc', '/sys')):
                                    if not target.startswith(self.app_root):
                                        self.log_event(
                                            event_type='path_traversal',
                                            evidence='file_access',
                                            details={
                                                'path': target,
                                                'pid': pid,
                                                'process': Path(process_name).name,
                                                'reason': 'outside_app_root'
                                            }
                                        )

                            except (FileNotFoundError, PermissionError, OSError):
                                # FD may have closed
                                continue

                except (ValueError, FileNotFoundError, PermissionError):
                    continue

        except Exception as e:
            print(f"[{self.timestamp()}] WARNING: Error checking file access: {e}", file=sys.stderr)

    def parse_proc_net_tcp(self, path: str) -> Set[Tuple[str, str]]:
        """
        Parse /proc/net/tcp or /proc/net/tcp6 to extract connections.

        Returns set of (local_addr, remote_addr) tuples.
        Format: "192.168.1.100:45678" -> "93.184.216.34:443"
        """
        connections = set()

        try:
            with open(path, 'r') as f:
                lines = f.readlines()[1:]  # Skip header

            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue

                local_addr = parts[1]
                remote_addr = parts[2]
                state = parts[3]

                # Parse hex addresses
                local_ip, local_port = self._parse_hex_addr(local_addr)
                remote_ip, remote_port = self._parse_hex_addr(remote_addr)

                # Skip if remote is 0.0.0.0:0 (not connected)
                if remote_ip == '0.0.0.0' and remote_port == 0:
                    continue

                # Skip LISTEN state (state == 0A)
                if state == '0A':
                    continue

                local_str = f"{local_ip}:{local_port}"
                remote_str = f"{remote_ip}:{remote_port}"
                connections.add((local_str, remote_str))

        except FileNotFoundError:
            pass  # IPv6 may not exist
        except Exception as e:
            print(f"[{self.timestamp()}] WARNING: Error parsing {path}: {e}", file=sys.stderr)

        return connections

    def _parse_hex_addr(self, hex_addr: str) -> Tuple[str, int]:
        """
        Parse hex address from /proc/net/tcp.

        Format: "0100007F:1F90" -> ("127.0.0.1", 8080)
        IPv6 Format: "00000000000000000000000001000000:1F90" -> ("::1", 8080)
        """
        try:
            hex_ip, hex_port = hex_addr.split(':')
            port = int(hex_port, 16)

            # Detect IPv6 (32 hex chars)
            if len(hex_ip) == 32:
                # IPv6 in reverse byte order
                ip_bytes = bytes.fromhex(hex_ip)
                # Convert to standard notation
                groups = []
                for i in range(0, 16, 2):
                    groups.append(f"{ip_bytes[i+1]:02x}{ip_bytes[i]:02x}")
                ip = ':'.join(groups)
                # Simplify
                ip = self._simplify_ipv6(ip)
            else:
                # IPv4 in reverse byte order
                ip_int = int(hex_ip, 16)
                ip = '.'.join([
                    str((ip_int >> 0) & 0xFF),
                    str((ip_int >> 8) & 0xFF),
                    str((ip_int >> 16) & 0xFF),
                    str((ip_int >> 24) & 0xFF)
                ])

            return ip, port

        except Exception as e:
            print(f"[{self.timestamp()}] WARNING: Error parsing hex addr {hex_addr}: {e}", file=sys.stderr)
            return "0.0.0.0", 0

    def _simplify_ipv6(self, ipv6: str) -> str:
        """Simplify IPv6 address (e.g., 0000:0000:0000:0000:0000:0000:0000:0001 -> ::1)."""
        try:
            # Basic simplification
            groups = ipv6.split(':')
            # Remove leading zeros
            groups = [g.lstrip('0') or '0' for g in groups]
            # Join back
            result = ':'.join(groups)
            # Replace longest sequence of 0s with ::
            result = result.replace(':0:0:0:0:0:0:0:', '::')
            result = result.replace(':0:0:0:0:0:0:', '::')
            result = result.replace(':0:0:0:0:0:', '::')
            result = result.replace(':0:0:0:0:', '::')
            result = result.replace(':0:0:0:', '::')
            result = result.replace(':0:0:', '::')
            return result
        except Exception:
            return ipv6

    def check_outbound_connections(self):
        """Check for unexpected outbound connections (SSRF indicator)."""
        try:
            # Get current connections
            current_conns = self.parse_proc_net_tcp('/proc/net/tcp')
            current_conns.update(self.parse_proc_net_tcp('/proc/net/tcp6'))

            for local_addr, remote_addr in current_conns:
                # Skip if already in baseline
                if (local_addr, remote_addr) in self.known_connections:
                    continue

                # Parse remote IP
                remote_ip = remote_addr.split(':')[0]

                # Check for metadata endpoints
                if remote_ip in self.METADATA_IPS:
                    self.log_event(
                        event_type='ssrf',
                        evidence='outbound_connection',
                        details={
                            'local': local_addr,
                            'remote': remote_addr,
                            'reason': 'metadata_service'
                        }
                    )
                # Check for unexpected external connections
                elif not self._is_local_ip(remote_ip):
                    self.log_event(
                        event_type='ssrf',
                        evidence='outbound_connection',
                        details={
                            'local': local_addr,
                            'remote': remote_addr,
                            'reason': 'external_connection'
                        }
                    )

                # Add to known connections to avoid duplicate alerts
                self.known_connections.add((local_addr, remote_addr))

        except Exception as e:
            print(f"[{self.timestamp()}] WARNING: Error checking connections: {e}", file=sys.stderr)

    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is localhost/private."""
        if ip in ('127.0.0.1', '::1', 'localhost'):
            return True
        if ip.startswith('127.'):
            return True
        if ip.startswith('10.'):
            return True
        if ip.startswith('172.'):
            try:
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    return True
            except (ValueError, IndexError):
                pass
        if ip.startswith('192.168.'):
            return True
        if ip.startswith('fe80:'):  # Link-local IPv6
            return True
        if ip.startswith('fc00:') or ip.startswith('fd00:'):  # ULA IPv6
            return True
        return False

    def run(self):
        """Main monitoring loop."""
        print(f"[{self.timestamp()}] Starting victim monitor for agent: {self.agent_name}")
        print(f"  - Log file: {self.log_path}")
        print(f"  - App root: {self.app_root}")
        print(f"  - Poll interval: {self.poll_interval}s")
        print(f"  - Monitor PID: {self.my_pid}")

        self.setup_signal_handlers()

        # Collect baseline
        self.collect_baseline()

        if not self.running:
            print(f"[{self.timestamp()}] Interrupted during baseline collection")
            return

        print(f"[{self.timestamp()}] Starting active monitoring...")

        # Main monitoring loop
        while self.running:
            try:
                self.check_new_processes()
                self.check_file_access()
                self.check_outbound_connections()

                time.sleep(self.poll_interval)

            except Exception as e:
                print(f"[{self.timestamp()}] ERROR: Monitoring loop error: {e}", file=sys.stderr)
                time.sleep(self.poll_interval)

        print(f"[{self.timestamp()}] Monitor shutdown complete")


def main():
    """Main entry point."""
    # Read configuration from environment
    config = {
        'agent_name': os.getenv('AGENT_NAME', 'unknown'),
        'log_dir': os.getenv('LOG_DIR', '/logs'),
        'app_root': os.getenv('APP_ROOT', '/app'),
        'poll_interval': float(os.getenv('POLL_INTERVAL', '0.25')),
        'startup_grace': float(os.getenv('STARTUP_GRACE_PERIOD', '30')),
    }

    # Validate configuration
    if config['agent_name'] == 'unknown':
        print("ERROR: AGENT_NAME environment variable not set", file=sys.stderr)
        sys.exit(1)

    # Create and run monitor
    monitor = VictimMonitor(config)
    monitor.run()


if __name__ == '__main__':
    main()
