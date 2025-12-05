## Prowler

---

```bash
git clone <https://github.com/prowler-cloud/prowler.git>
cd prowler
pip3 install -r requirements.txt
```

```bash
aws configure
```

```python
./prowler -M html -V
```
## Scoutsuite

---
```bash
git clone <https://github.com/nccgroup/ScoutSuite.git>
cd ScoutSuite
pip3 install -r requirements.txt
```
```bash
python3 scout.py aws --report-dir ./scoutsuite_report --debug
```
```bash
python3 scout.py aws --list-services
```
## Pacu (Interactive AWS Attack Framework)
___
```bash
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu
pip3 install -r requirements.txt
```
```bash
python3 pacu.py
```
**Import credentials (if needed) and enumerate permissions:**
```bash
>> import_keys --all      # Automatically load all AWS credentials from ~/.aws or environment
>> run iam__enum_permissions
```