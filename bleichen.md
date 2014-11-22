I started by decompiling the Java file, which gave me the port to connect to (4919). I then took a look at the signature verification algorithm and wrote a Python equivalent:

```
def verify(one, two):
    """
    x^3 == 1ffffffffff{hash}anything
    """
    getcontext().prec = 1000

    one = hashlib.sha1(one.encode("utf8")).hexdigest()
    two = hex(int((Decimal(int(two, 16))**3) % N))[2:].strip("L").zfill(768)

    print(one, two)

    if two.index("0001ffffffffff") == 0 and one in two:
        print("passed 10 fs check and contains check")
        for i in range(two.index("f"), two.index(one) - 2):
            print("on index %d..." % i)
            if two[i] != "f":
                print("failed! not f")
                return False
        print("for passed!")
        if two[two.index(one) - 2] != "0" or two[two.index(one) - 1] != "0":
            print("failed! indexing check w/ 0")
            return False
        return True
    else:
        return False
```

Based on this, I wrote a function to find a valid signature (i.e. one that matched the pattern "1ffffffffff{hash_of_command}anything"):

```
def guess(one):
    getcontext().prec = 1000

    one = hashlib.sha1(one.encode("utf8")).hexdigest()
    mini = Decimal(int("0001ffffffffff00%s%s" % (one, '7' * 712), 16))
    maxi = Decimal(int("0001ffffffffff00%s%s" % (one, 'f' * 712), 16))
    # print(mini, maxi)

    third = Decimal(1/Decimal(3))
    value1 = mini ** third
    value2 = maxi ** third
    return (hex(int(((value1 + value2) / Decimal(2))))[2:].strip("L"))
```

I just ran the guess() function on the strings "ls" and "cat" which allowed me to generate valid signatures for flags:

```
# ls
# 7fffffffffeabe552908539123fadd400fbe7e0f52dad18bfb9f769757dae2a008d47be25f7e3236b8cb6cdc0d56a69c2b30da0f1c65a8039a7a1b3b4182dacfb946a4cd283900f1701889919e1f408d3fc10c4a318d28c9b57aaed2ad3d9173633cc6ea24ac5c56d0785d7939e17b7060a4c79211248010dc6ee5c667ad335

# cat
# 7fffffffffeab7ccb7e1151dde4920716e7822264ba7031df08d08d52c784be24d8423fa7c0c3c98678eadc1e6761c0fdca1a648d1b0b2fd79495956bc64ea1aaaaf308485a57649c8218b0f709ef03b00736faed7e1ccbd9b9cc02f4fd313bf24aa91076d195d7eea1820256394da73a483ce098e3f106a3fce2c1cd53089a
```

The Decimal library was used because we were dealing with really big numbers. Other things to note -- N didn't actually matter, because all numbers used were less than N (so there was no need to do modulus).
