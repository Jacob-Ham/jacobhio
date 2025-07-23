___
**Enable monitor mode**

```bash
sudo airmon-ng start wlan0
```

Confirm with iwconfig
```bash
iwconfig

eth0      no wireless extensions.

wlan0mon  IEEE 802.11  Mode:Monitor  Frequency:2.457 GHz  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
lo        no wireless extensions.
```

now scan for networks

This will output details about access points (including channel IDs)
```bash
sudo airodump-ng wlan0mon
```


**Scanning Specific Channels or a Single Channel**

The command `airodump-ng wlan0mon` initiates a comprehensive scan, collecting data on wireless access points across all the channels available. 

 we can specify a particular channel using the `-c` option to focus the scan on a specific frequency. For instance, `-c 11` would narrow the scan to channel 11. This targeted approach can provide more refined results, especially in crowded Wi-Fi environments.

```bash
sudo airodump-ng -c 11 wlan0mon
```

It is also possible to select multiple channels for scanning using the command 

```bash
airodump-ng -c 1,6,11 wlan0mon
```

**Scanning 5 GHz Wi-Fi bands**

By default, airodump-ng is configured to scan exclusively for networks operating on the 2.4 GHz band. Nevertheless, if the wireless adapter is compatible with the 5 GHz band, we can instruct airodump-ng to include this frequency range in its scan by utilizing the `--band` option. You can find a list of all WLAN channels and bands available for Wi-Fi [here](https://en.wikipedia.org/wiki/List_of_WLAN_channels).

- `a` uses 5 GHz
- `b` uses 2.4 GHz
- `g` uses 2.4 GHz

```bash
sudo airodump-ng wlan0mon --band a
```

You can also dump across channels

```bash
sudo airodump-ng --band abg wlan0mon
```

**Save output to file**

```bash
airodump-ng wlan0mon --write outFile 
```
will generate `.cap, .csv, kismet.csv, kismet.netxml, log.vsc` by default

