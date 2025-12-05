---
tags:
  - "#stage/reconnaissance"
  - "#os/linux"
  - "#tool/nmap"
  - "#tool/mount"
  - "#tool/showmount"
  - "#tool/netexec"
  - "#technique/T1135"
  - "#tactic/TA0007"
  - "#type/technique"
  - privileges/unauthenticated
aliases:
  - Network File System Enumeration
  - Enumerate NFS Shares
---

## Technique
___

NFS (Network File System) enumeration is a reconnaissance technique used to identify shared directories on a network that are exported via the NFS protocol. Attackers use this to discover misconfigurations that could allow unauthorized access to sensitive data, or to gain a foothold for lateral movement. The primary goal is to find NFS servers, list their exported shares, and identify weak permissions that could allow read or write access.

## Prerequisites
___

**Access Level:** Network access to the target host(s). No authentication is typically required for the initial enumeration phase.

**System State:** The target host must have the NFS service running, usually on TCP/UDP ports 2049, and the portmapper service on TCP/UDP 111.

**Information:** You need the IP address or hostname of the target host or network range.

## Execution
___

### 1. Identifying NFS Services

#### **Nmap**

The most common way to discover NFS services is to scan a network range for open ports. Nmap's default scripts can detect and enumerate NFS.

To scan an entire subnet and identify hosts with NFS services running:

```
nmap -sV -p 111,2049 --script nfs-showmount <target_IP_range>
```

The `-sV` flag performs service and version detection, which helps confirm that the service on port 111 is indeed `rpcbind` and that NFS is running on 2049.

### 2. Identifying Accessible Exports

#### **showmount**

Once you have identified a host running NFS, the `showmount` command is a simple and effective tool to see which directories it is exporting. The `-e` flag lists all exported file systems.

```
showmount -e <target_IP>
```

If the output shows a share is exported to `*` or `(everyone)`, it means it's accessible to any host on the network.

#### **Nmap**

The `nfs-showmount` script used in the previous step also serves this purpose, providing a list of all shares that the server is exporting.

```
nmap -sV --script nfs-showmount <target_IP>
```

### 3. Connecting and Pillage

After identifying an open NFS share, you can attempt to mount it on your local machine to access its contents.

**Mounting the share**:

1. Create a local directory to act as the mount point:

```bash
mkdir /tmp/nfs_share
```

2. Mount the remote share to your local directory:

```bash
mount -t nfs <target_IP>:/<exported_share_name> /tmp/nfs_share
```

For example: 
`mount -t nfs 192.168.1.100:/home/shared_docs /tmp/nfs_share`


**Pillaging the data**: Once the share is mounted, you can navigate the directory and view its contents as if it were a local folder on your machine. You can use standard commands like `ls`, `cd`, `cat`, and `cp` to explore and exfiltrate files.

**Escalating privileges with `no_root_squash`**: A major vulnerability to look for is the `no_root_squash` option. If this is enabled on the server, a client with root privileges on their local machine can act as root on the NFS share. To exploit this:

1. On your local machine, create a new user with the UID of 0 (root):

```bash
sudo useradd -ou 0 -g 0 newrootuser
```

2. Switch to the new user:

```bash
sudo su - newrootuser
```

2. Mount the NFS share with the new user. You will now have root-level permissions on the mounted share, allowing you to read or even modify files that a normal user could not access.


#### **NetExec**

NetExec (nxc) can be used to enumerate NFS shares and identify vulnerabilities as part of a larger network assessment.

```
nxc nfs <IP>
```

This command will enumerate exported shares and report on any misconfigurations like `no_root_squash`.

## Cleanup Considerations
___

- Unmount the NFS share after you are finished to avoid a hanging filesystem.

- `umount /tmp/nfs_share`

- Remove the user created for exploitation.

## Detection & Mitigation
___

#### Detection

- **Network Traffic Analysis:** Monitor for `mount` or RPC requests originating from unexpected IP addresses.
- **System Logs:** Look for unusual activity in system logs related to NFS mounts, especially from unauthorized hosts.

#### Mitigation

- **Restrict Exports:** Only export NFS shares to specific, trusted IP addresses or subnets. Avoid using `(everyone)` or `*`.
- **Disable `no_root_squash`**: Ensure this option is not enabled on any exported shares unless absolutely necessary and with strong access controls in place.
- **Least Privilege:** Apply the principle of least privilege. Configure shares to provide only the permissions (read-only, etc.) that users need.
- **Firewall:** Restrict access to ports 111 and 2049 at the host and network firewall levels.