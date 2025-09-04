___

**Starting monitor mode**

Identify interface name
```bash
sudo airmon-ng
```

Enable monitor mode

```bash
sudo airmon-ng start wlan0
```

When putting a card into monitor mode, it will automatically check for interfering processes. It can also be done manually by running the following command:

```bash
sudo airmon-ng check
```

we can terminate these processes using the airmon-ng check kill command.

```bash
sudo airmon-ng check kill
```

**Use specific channel**
```bash
sudo airmon-ng start wlan0 11
```

monitor mode on channel 11. This ensures that the wlan0 interface operates specifically on channel 11 while in monitor mode.

We can stop the monitor mode on the `wlan0mon` interface using the command `airmon-ng stop wlan0mon`.

```bash
sudo airmon-ng stop wlan0mon
```

