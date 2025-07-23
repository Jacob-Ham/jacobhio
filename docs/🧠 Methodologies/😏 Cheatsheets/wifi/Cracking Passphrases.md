
Make sure you have a powerful enough system to perform cracking operations
```bash
aircrack-ng -S

1628.101 k/s
```

The above output estimates that our CPU can crack approximately 1,628.101 passphrases per second.

#### Cracking WEP

Aircrack-ng is capable of recovering the WEP key once a sufficient number of encrypted packets have been captured using Airodump-ng. It is possible to save only the captured IVs (Initialization Vectors) using the `--ivs` option in Airodump-ng. Once enough IVs are captured, we can utilize the `-K` option in Aircrack-ng, which invokes the Korek WEP cracking method to crack the WEP key.

```bash
aircrack-ng -K cap.ivs 
```

#### Cracking WPA

We need to first capture a four-way handshake, then we can use a dictionary attack to try to crack the key.

Aircrack truly only needs two packets  Specifically, EAPOL packets 2 and 3, or packets 3 and 4, are considered a full handshake.

```bash
aircrack-ng WPA.pcap -w /opt/wordlist.txt
```



