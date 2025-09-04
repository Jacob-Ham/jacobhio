
First scan for available networks
```bash
sudo airodump-ng wlan0mon
```

Find the network you're trying to connect to and copy one of the clients mac addresses.

!!! alert "Just stealing a client mac might suck due to mac collisions. "

A better method is to either 1. deauth the client or 2. wait for the client to disconnect naturally before connecting. 

We can also check if there is a 5 GHz band available for the ESSID. If the 5 GHz band is available, we can attempt to connect to the network using that frequency, which would avoid collision events since most clients are connected to the 2.4 GHz band.

```bash
sudo airodump-ng wlan0mon --band a
```

https://github.com/alobbs/macchanger

```bash
sudo macchanger wlan0
```

**Change mac:**

```bash
sudo ifconfig wlan0 down
```
```
sudo macchanger wlan0 -m 3E:48:72:B7:62:2A
```
```bash
sudo ifconfig wlan0 up
```

now try to connect! 

