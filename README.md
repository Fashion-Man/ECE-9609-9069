# SQL injection vulnerability(CVE-2022-24260)
## Useful links:
[CVE-2022-24260](https://www.cvedetails.com/cve/CVE-2022-24260/)

## What is SQL injection
SQL Injection is a security vulnerability that occurswhen you ask a user for input, and it is the most common and simplest vulnerability in websites.[^1] The main reason is that the program does not judge and process the legitimacy of the user input data, so that the attacker can add additional SQL statements to the predefined SQL statements in the Web application, and perform illegal operations without the administrator's knowledge. In this way, the database server can be deceived to execute unauthorized arbitrary queries, thereby further obtaining data information.

The following example is a SQL injection process.[^1]

Simple code about selecting a user.
```SQL
txtUserId = getRequestString("UserId");
txtSQL = "SELECT * FROM Users WHERE UserId = " + txtUserId;
```
If there is nothing can avoid the user enter the "smart" input, then the user can enter: 

User ID: " or ""="

Password: " or ""="

A valid SQL statement will be created:
```SQL
SELECT * FROM Users WHERE Name ="" or ""="" AND Pass ="" or ""=""
```
This SQL statement will return all usernames and corresponding passwords.


## References
[^1]: https://www.w3schools.com/sql/sql_injection.asp
