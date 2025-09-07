___
You can dump potentially dump all DNS entries with a low privilege account via ADI. This can help identify new applications behind hostnames that may have just been reporting a blank IIS page. 

### TL;DR

**Using:** [adidnsdump](https://github.com/dirkjanm/adidnsdump)

```bash
git clone https://github.com/dirkjanm/adidnsdump.git
cd adidnsdump
python3 -m venv adidns-venv
source ./adidns-venv/bin/activate
pip3 install .
```

#### Usage

**Display the zones in the domain where you are currently in**

```bash
adidnsdump -u domain\\user --print-zones dc01.domain.local
```

**Dump & Resolve Records in default zone** (will output `records.csv`)

```bash
adidnsdump -u domain\\user dc01.domain.local -r 
```

Specify zone:
```bash
adidnsdump -u domain\\user --zone <zone> dc01.domain.local -r
```

