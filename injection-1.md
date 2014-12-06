# Injection 1 Writeup
##### By traceAnsible of TJ CSL


Injection 1 provides the source of the login script. 

```php
$username = $_POST["username"];
$password = $_POST["password"];
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($con, $query);

if (mysqli_num_rows($result) !== 1) {
    echo "<h1>Login failed.</h1>";
} else {
    echo "<h1>Logged in!</h1>";
    echo "<p>Your flag is: $FLAG</p>";
}
```
(for brevity i've removed their debugging stuff)

We know we need the query on line 3 to return only a single result, and that the username field is just thrown into the query with no 
sanitzation whatsoever. 

Passing username as 
 ' OR '1'='1'

will remove the need to get the correct username, and adding -- to the end will comment our the rest of the query.

That query returns all possible users, which won't let us log in since the code wants only one user. 

Simply adding "LIMIT 1" before the comment this problem.

The final usename value is

 ' OR '1' = '1'  LIMIT 1 -- 

The password value doesn't matter.


Happy Hacking!
