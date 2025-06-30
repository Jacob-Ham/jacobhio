**Dorks**
```Python
site:site.com filetype:pdf
```
- [crt.sh](http://crt.sh/) - search through certificates
```Python
%.site.com
```
**Asset finder:** [https://github.com/tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder)
```Python
assetfinder <DOMAIN>
```
```Python
assetfinder <DOMAIN> | grep <DOMAIN> | sort -u
```
**amass**
```Python
amass enum -d <DOMAIN>
```
**httpprobe**
```Python
cat <SUBDOMAINSLIST> | grep <domain> | sort -u | httpprobe -prefer-https | grep https
```
