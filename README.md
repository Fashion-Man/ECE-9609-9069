# SQL injection vulnerability(CVE-2022-24260)
## Useful links:
[CVE-2022-24260](https://www.cvedetails.com/cve/CVE-2022-24260/)

[SQL Injection(Wikipedia)](https://en.wikipedia.org/wiki/SQL_injection)

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

The flow chart of Keylogger[^2]:
![alt text](https://github.com/Fashion-Man/ECE-9609-9069/blob/319bc06d23bd3e178305e3984bd1e1eda1ad9d09/sql%20flowchart.png)

## A SQL injection vulnerability in Voipmonitor GUI(CVE-2022-24260)
This new sql injects for unauthenticated users allowing gaining admin privileges[^3]
![alt text](https://github.com/Fashion-Man/ECE-9609-9069/blob/2096952ca2904c53f01479636923d7ca39375454/cvss.png)

## How to fix the SQL vulnerability
Since websites typically require sustained access to databases, very little and often no defense is given by firewalls against SQL injection attacks and every visitor on a website should be given access to the database. Furthermore, since antivirus programs are expected to identify and halt incoming data of a very different kind, they are equally ineffective against stopping SQL injection vulnerabilities. 

Two parts make up a defense against SQL injection vulnerabilities. The first defense is to perform routine updates of all servers and applications as well as patching all servers and applications. The second part of the defense is to mitigate attacks by assembling well-written code as well as well tested code that can prohibit SQL commands that are not foreseen.  

Given these defenses, the question then rises; why are SQL injections a threat and why is the number of successful attacks rising?

Many factors contribute to the answer of this question. 
Firstly, the number of servers,volume and applications of code are rapidly increasing on web sites. Furthermore, they interact with each other in uncertain ways. Another reason could be that activities such as updating and patching servers and applications routinely that are important to defending websites may be postponed by IT departments too often which leaves websites vulnerable to attacks. Another issue that creates hidden holes in security routines is a high staff turnover and layoff rate. Lastly and simply, the number of attacks on websites and the tools required to successfully hack websites is increasing at a constant rate. To be protected, security checks must be consistent and diligent. 


## References
[^1]: https://www.w3schools.com/sql/sql_injection.asp
[^2]: https://portswigger.net/web-security/sql-injection
[^3]: https://www.cvedetails.com/cve/CVE-2022-24260/
