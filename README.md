# NetBackup 11.1 Vmware workload "agentless" file recovery
## API POC - File level VM restore health check
## Prerequisites

- NetBackup 10.5/11.1 master server
- VxUpdate EEB package in the master EEB repo for the version of NBU master
- /recovery directory in VM writable by VM user defined (needed for the VxUpdate package extraction needed for recovery)
- Need NetBackup Admin (RBAC Admin role) user creds
- VM user must have drop-in sudoers file Example: -> /etc/sudoers.d/vmuser
- VM user must be member of wheel/sudo group
```
vmuser ALL = (root) NOPASSWD : ALL
vmuser ALL=(root) NOPASSWD: /usr/bin/tar
```

### Required Arguments for config.json
- master = FQDN of master server
- username = NetBackup Web UI admin username (non-root user must be in RBAC role for admin)
- password = NetBackup Web UI password
- vm_name = hostname of VM to recover
- vm_username = userid
- vm_password = password
- files = File(s) to be recovered
- destination = Path to recover file(s) to
- no_check_certificate = For self signed TLS


# Example run with self-signed cert on master
```
./vm_recover.py --config config.json
```

### References:
- https://github.com/VeritasOS/netbackup-api-code-samples
- https://sort.veritas.com/public/documents/nbu/11.1/windowsandunix/productguides/html/getting-started/
- https://sort.veritas.com/public/documents/nbu/11.1/windowsandunix/productguides/html/recovery/#/VMware%20Workloads/post_recovery_workloads_vmware_scenarios_guestfs_agentless_recover
