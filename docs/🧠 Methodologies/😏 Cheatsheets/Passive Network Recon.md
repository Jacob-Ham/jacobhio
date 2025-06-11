___
## Host discovery
### DHCP
dhcpdump
```bash
sudo dhcpdump -i eth0
```
zeek
```bash
sudo zeek -i eth0 local
```
### ARP
tcpdump
```bash
sudo tcpdump -n -i eth0 arp
```