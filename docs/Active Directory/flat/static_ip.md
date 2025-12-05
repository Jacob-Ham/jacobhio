---
tags:

- "#type/technique"
- "#tactic/TA0008"
- "#technique/T1562002"
- "#stage/configuration-management"
- "#os/linux"
- "#tool/netplan"

aliases:

- Configure Static IP on Ubuntu
- Netplan Static IP

---

## Technique
---

Configuring a static IP address on an Ubuntu system is a fundamental system administration task. A static IP ensures the machine's address remains consistent, which is essential for servers and services that need to be reliably accessible on a network, such as web servers, database servers, and firewalls. This note outlines how to configure, apply, and remove a static IP using Netplan, the default network configuration tool for modern Ubuntu distributions.

## Prerequisites
---

**Access Level:** Root or sudo privileges on the Ubuntu system.

**System State**: Ubuntu Server 18.04 LTS or newer (or Desktop with Netplan installed).

**Information:** You will need the following network details from your network administrator or router:

- IP Address: The static address you wish to assign (e.g., 192.168.1.50). Subnet Mask: The subnet in CIDR notation (e.g., /24).

- Gateway: The IP address of your default gateway (e.g., 192.168.1.1).

- DNS Servers: One or more DNS server addresses (e.g., 8.8.8.8, 8.8.4.4).

## Execution
---
#### **Identify Your Network Interface**

Before making changes, identify the name of the network interface you want to configure. This is typically something like eth0 or enp0s3.

```bash
ip a
```

#### Configure the Static IP with Netplan

Netplan configurations are stored in YAML files in the /etc/netplan/ directory. You will likely find a file named something like 01-netcfg.yaml or 50-cloud-init.yaml.

Open the configuration file with your preferred text editor (e.g., nano).

```bash
sudo nano /etc/netplan/01-netcfg.yaml
```

Modify the file to replace the dhcp4: true setting with the static IP details. The syntax is very specific, so pay close attention to indentation.

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 192.168.1.50/24
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
```

- `renderer`: Specifies the backend for network management. Use `networkd` for most systems.
- `enp0s3`: Replace with your actual network interface name.
- `addresses`: Use CIDR notation for the IP address and subnet mask.
- `routes`: Defines the default gateway.
- `nameservers`: A list of DNS servers.


#### Apply the Configuration

After saving the file, apply the changes using the netplan apply command.

```bash
sudo netplan apply
```

This command will apply the configuration without a reboot. If there are any syntax errors in your YAML file, Netplan will report them.

#### Verify the Configuration

Verify the new IP address has been assigned and network connectivity is working.

```bash
ip a
```

#### Reverting to DHCP

To revert to a dynamic IP address, edit the Netplan configuration file and change the addresses and nameservers sections back to dhcp4: true.

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: yes
```

#### Apply the changes:

```bash
sudo netplan apply
```

## Cleanup Considerations
---

Ensure you save a backup of the original /etc/netplan/ file before making changes.

Be aware that incorrect YAML syntax can cause network connectivity to fail. Always run sudo netplan try first to test the configuration. netplan try will revert the changes if you don't confirm them within 120 seconds.

## Detection & Mitigation
---
### Detection

- System Logs: Look for changes in /var/log/syslog related to netplan or systemd-networkd.

- File Integrity Monitoring (FIM): Monitor the /etc/netplan/ directory for any file modifications.

### Mitigation

- Principle of Least Privilege: Restrict access to the sudo group and other users who can modify system files.

- Configuration Management: Use a configuration management tool like Ansible or Puppet to manage network settings, ensuring changes are tracked and auditable.