---
author: embe221ed
layout: post
title:  "madcore"
date:   2022-07-15 05:00:00 +0200
tags:   pwn writeup
toc:    true
categories: writeup pwn
---

## introduction

`madcore` was a pwn task from [Google CTF 2022][googlectf]. It is a coredump helper
that parses the input as _coredump_ file and produces some results.
<!--more-->

### files

We are provided with few files:
+ `Dockerfile`
+ `flag`
+ `ld-linux-x86-64.so.2`
+ `libc.so.6`
+ `libstdc++.so.6`
+ `madcore`
+ `nsjail.cfg`

> download: [madcore.zip][madcore_zip]

### interface

`madcore` interface is simple. Just write bytes to it and it will count them until enough bytes is sent.

```bash
➜  madcore git:(main) ✗ ./madcore
abcd    # input bytes
Read 5  # counts bytes
```

so, I think it's time to prepare a _coredump_ file to send.

## coredump

### what is coredump file?

> A core dump is a file containing a process's address space (memory) when the process terminates unexpectedly. Core dumps may be produced on-demand (such as by a debugger), or automatically upon termination. Core dumps are triggered by the kernel in response to program crashes, and may be passed to a helper program (such as systemd-coredump) for further processing - [Arch Linux wiki](https://wiki.archlinux.org/title/Core_dump)

There is an interesting post covering _coredump_ file structure [here](https://www.gabriel.urdhr.fr/2015/05/29/core-file/).

### generate coredump file

I've tried to generate a _coredump_ file by simply causing `SEGFAULT` in my C++ program:

```bash
➜  crash git:(main) ✗ ls
test.cpp
➜  crash git:(main) ✗ ccat test.cpp       
0001: #include <iostream>
0002: using namespace std;
0003: int main(){
0004:    int arr[2];
0005:    arr[3] = 10;
0006:    return 0;
0007: }
0008: 
➜  crash git:(main) ✗ g++ test.cpp -o test
➜  crash git:(main) ✗ ls
test  test.cpp
➜  crash git:(main) ✗ ./test
*** stack smashing detected ***: terminated
[1]    13827 abort (core dumped)  ./test
➜  crash git:(main) ✗ ls
test  test.cpp
```

but no _coredump_ file is there...

There were two reasons why my _coredump_ file was not generated:
1. core dump size limit
2. core_pattern

```bash
➜  crash git:(main) ✗ sudo sysctl -w kernel.core_pattern=core.%u.%p.%t # to enable core generation
kernel.core_pattern = core.%u.%p.%t
➜  crash git:(main) ✗ ulimit -c unlimited # set core dump size to unlimited
➜  crash git:(main) ✗ ./test
*** stack smashing detected ***: terminated
[1]    14162 abort (core dumped)  ./test
➜  crash git:(main) ✗ ls    
core.1001.14162.1657865437  test  test.cpp
```

That way, I was able to generate valid _coredump_ file to provide it to `madcore`

### send coredump to madcore

At first, I was sending the _coredump_ file but the program wouldn't stop reading bytes...
I had to take a quick look at the decompiled code to see what is going on.
The reading is performed in `main()` function, just at the beginning.

```cpp
buffer = (uchar *)malloc(0x1000000);
memset(buffer,0,size);
temp_buffer = buffer;
length = 0;
while (size != 0) {
  _length = read(0,temp_buffer,size);
  length = (int)_length;
  if (length < 1) break;
  size = size - (long)length;
  temp_buffer = temp_buffer + length;
  printf("Read %d\n",length);
}
```

So, I have to send exactly `0x1000000` bytes. I prepared simple python script to do that easily.

```python
size = 0x1000000

with open(args.CORE, "rb") as coredump:
    data = bytearray(coredump.read())

data_len = len(data)
assert data_len < size
log.info(f"len: {data_len}")
io.send(data)
io.send(b"\x00"*(size-data_len))
io.recvuntil(b"FINISHED READING.\n", drop=True)
io.interactive()
```

And here is the result:

```bash
➜  writeup git:(main) ✗ ./solve.py CORE=crash/core.1001.14162.1657865437
[*] '/home/[REDACTED]/madcore'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/[REDACTED]/madcore': pid 15815
[*] len: 507904
[*] Switching to interactive mode
{"backtrace":[[0,"<unknown>"],[2137,"??\n??:0:0\n\n"],[438894,"??\n??:0:0\n\n"],[438366,"??\n??:0:0\n\n"],[438540,"??\n??:0:0\n\n"],[438366,"??\n??:0:0\n\n"],[153840,"0x328\n"]],"modules":["/home/[REDACTED]/crash","/usr/lib/x86_64-linux-gnu/ld-2.31.so","/usr/lib/x86_64-linux-gnu/libc-2.31.so"]}[*] Got EOF while reading in interactive
$  
```

We can interact with the program, let's see what is happening inside!

## reverse engineering

### main()

After the reading ends, the `Corefile::Corefile()` object is initialized with the buffer.

```cpp
Corefile corefile = Corefile::Corefile(buffer, (long)temp_buffer - (long)buffer);
corefile.Process();
corefile.GetRegisters();
```

#### Corefile::Corefile()

The `Corefile::Corefile()` constructor:
+ initializes `ELFBinary` object
+ initializes `std::map<unsigned long, ELFBinary*>` - with key being address of ELF and value being pointer to `ELFBinary`
+ initializes `std::vector` for `Binary` pointers
+ initializes `std::vector` for `RegisterSet` pointers

#### Corefile::Process()

The `Corefile::Process()` function:
+ iterates over all `ELFBinary` objects

#### Corefile::GetRegisters()

The `Corefile::GetRegisters()` function:
+ iterates over all `process_headers` and runs `Corefile::ProcessNotes()` for specific headers

Here, the initialization is done. After that, the program gets into loop that iterates over all threads:

```cpp
while (threads = corefile.GetNumberOfThreads(), thread_num < threads) {
  backtrace = corefile.GetBacktrace(thread_num);
  registerSet = corefile.GetMappedRegisterSet(thread_num);
  frameCount = backtrace.GetFrameCount();
  endFrameCount = frameCount;
  for (currFrameIdx = 0; currFrameIdx < endFrameCount; currFrameIdx = currFrameIdx + 1) {
    callFrame.field0_0x0 = backtrace->frames[currFrameIdx].field0_0x0;
    callFrame.field1_0x8 = backtrace->frames[currFrameIdx].field1_0x8;
    callFrame.binary = backtrace->frames[currFrameIdx].binary;
    threads = callFrame.GetSP();
    binary = (Binary *)callFrame.GetBinary();
    Symbolizer::Symbolizer(local_298,binary,threads);
    Symbolizer::Symbolicate[abi:cxx11]();
    mappedAddr = callFrame.GetMappedAddress();
    /*
     * push a result with address to std::vector, pseudocode:
     */
     new_pair = std::make_pair<ulong, string>(mappedAddr, str);
     std::vector::push_back(new_pair);
  }
  thread_num = thread_num + 1;
}
```

## vulnerabilities

[googlectf]:    https://capturetheflag.withgoogle.com/challenges/pwn-madcore
[madcore_zip]:  https://embe221ed.dev/files/CTFs/GoogleCTF/2022/pwn/madcore/madcore.zip
