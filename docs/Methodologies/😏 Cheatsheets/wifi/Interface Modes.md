#### Managed Mode
This is usually the default mode for interfaces
```bash
 sudo ifconfig wlan0 down
 sudo iwconfig wlan0 mode managed
```
This mode allows us to authenticate and associate to an access point, basic service set, and others.

**Connect to network:**

```bash
sudo iwconfig wlan0 essid WIFI-TEST
```

#### Ad-hoc Mode

 This mode is peer to peer and allows wireless interfaces to communicate directly to one another. This mode is commonly found in most residential mesh systems for their backhaul bands.
 ```bash
 sudo iwconfig wlan0 mode ad-hoc
```
and connect
```bash
sudo iwconfig wlan0 essid WIFI-TEST
```

#### Master Mode

access point / router mode. This mode cannot be set with iwconfig because a management daemon is required. The easiest setup for this is using `hostapd`
Sample config:
```bash
$ nano open.conf
```
```bash
interface=wlan0
driver=nl80211
ssid=WIFI-TEST
channel=2
hw_mode=g
```
This configuration would simply bring up an open network, start the network with the following command: 
```bash
sudo hostapd open.conf
```

#### Mesh Mode
we can set our interface to join a self-configuring and routing network. This mode is commonly used for business applications where there is a need for large coverage across a physical space. 

Check if its even possible with the current interface:
```bash
sudo iw dev wlan0 set type mesh
```

#### Monitor/Promiscuous Mode

In this mode, the network interface can capture all wireless traffic within its range, regardless of the intended recipient. 
typically requires administrative privileges and may vary depending on the operating system and wireless chipset used

1. Bring the interface down

```bash
sudo ifconfig wlan0 down
```

2. set the interfaces mode

```bash
sudo iw wlan0 set monitor control
```

3. bring our interface back up.

```bash
sudo ifconfig wlan0 up
```

4. confirm mode

```bash
iwconfig

wlan0     IEEE 802.11  Mode:Monitor  Frequency:2.457 GHz  Tx-Power=30 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Power Management:off
```


#### Note on capabilities:

 If we are attempting to exploit WEP, WPA, WPA2, WPA3, and all enterprise variants, we are likely sufficient with just monitor mode and packet injection capabilities However, suppose we were trying to achieve different actions we might consider the following capabilities.

1. `Employing a Rogue AP or Evil-Twin Attack:` - We would want our interface to support master mode with a management daemon like hostapd, hostapd-mana, hostapd-wpe, airbase-ng, and others.
2. `Backhaul and Mesh or Mesh-Type system exploitation:` - We would want to make sure our interface supports ad-hoc and mesh modes accordingly. For this kind of exploitation we are normally sufficient with monitor mode and packet injection, but the extra capabilities can allow us to perform node impersonation among others.


