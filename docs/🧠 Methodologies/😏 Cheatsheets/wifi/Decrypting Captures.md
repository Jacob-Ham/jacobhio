We can decrypt `WEP`, `WPA PSK`, and `WPA2 PSK` captures with airdecap-ng. it can remove wireless headers from an unencrypted capture file. This tool is particularly useful in analyzing the data within captured packets by making the content readable and removing unnecessary wireless protocol information.

Airdecap-ng can be used for the following:

- Removing wireless headers from an open network capture (Unencrypted capture).
- Decrypting a WEP-encrypted capture file using a hexadecimal WEP key.
- Decrypting a WPA/WPA2-encrypted capture file using the passphrase.


```bash
airdecap-ng [options] <pcap file>
```

|**Option**|**Description**|
|---|---|
|`-l`|don't remove the 802.11 header|
|`-b`|access point MAC address filter|
|`-k`|WPA/WPA2 Pairwise Master Key in hex|
|`-e`|target network ascii identifier|
|`-p`|target network WPA/WPA2 passphrase|
|`-w`|target network WEP key in hexadecimal|
`Airdecap-ng` generates a new file with the suffix `-dec.cap`

the decrypted capture file using `airdecap-ng`, observe how the `Protocol` tab displays the correct protocol, such as ARP, TCP, DHCP, HTTP, etc. Additionally, notice how the `Info` tab provides more detailed information, and it correctly displays the `source` and `destination` IP addresses.

**Removing Wireless Headers from Unencrypted Capture file (open network):**

```
airdecap-ng -b <bssid> <capture-file>
```

Replace with the MAC address of the access point and with the name of the capture file.

```bash
sudo airdecap-ng -b 00:14:6C:7A:41:81 opencapture.cap
```

**Decrypting WEP-encrypted captures**

Requires hexadecimal WEP key
```bash
airdecap-ng -w <WEP-key> <capture-file>
```

**Decrypting WPA-encrypted captures**

Needs passphrase and essid of the network

```bash
airdecap-ng -p <passphrase> <capture-file> -e <essid>
```
