---
author: embe221ed
layout: post
title:  "madcore"
date:   2022-07-15 05:00:00 +0200
tags:   pwn binexp googlectf
toc:    true
categories: writeup
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

### functions

#### main()

The object `Corefile` is initialized with buffer just after the reading it. Then, the `Corefile::Process()` and `Corefile::GetRegisters()`
functions are called.

```cpp
Corefile corefile = Corefile::Corefile(buffer, (long)temp_buffer - (long)buffer);
corefile.Process();
corefile.GetRegisters();
```

#### Corefile::Corefile()

The `Corefile::Corefile()` constructor initializes:
+ `ELFBinary` object for buffer
+ `std::vector` for `Binary` pointers
+ `std::vector` for `RegisterSet` pointers
+ `ELFBinary` object for all ELF files that is finds in the buffer
+ `std::map<unsigned long, ELFBinary*>` - address of the `ELFBinary` in the buffer and address of the object

#### Corefile::Process()

The `Corefile::Process()` function:
+ iterates over all `ELFBinary` objects
+ runs `Corefile::ProcessLOADs()` function

#### Corefile::ProcessLOADs()

The `Corefile::ProcessLOADs()` function iterates over process headers and initializes `Binary` objects.

#### Corefile::GetRegisters()

The `Corefile::GetRegisters()` function iterates over all `process_headers` and runs `Corefile::ProcessNotes()` for specific headers

#### Corefile::ProcessNotes()

The `Corefile::ProcessNotes()` function iterates over the process memory and looks for process notes.
Depending on the note type it runs different parser functions to handle them, including:
+ `Corefile::ProcessSIGINFO()`
+ `Corefile::ParseNTFile()`
+ `Corefile::ParseAUXV()`
+ add `X86RegisterSet` to list of register sets of an object

#### Corefile::ParseNTFile()

```cpp
void __thiscall Corefile::ParseNtFile(Corefile *this,elf64_note *note) {
  /* variables */
  
  puVar2 = (note + (*note + 3U & 0xfffffffc) + 0xc);
  uVar1 = *(note + 4);
  size = *puVar2;
  buffer = malloc(size << 3);
  index = 0;
  local_20 = puVar2 + 2;
  while( true ) {
    if (size <= (ulong)(long)index) {
      local_18 = ((ulong)uVar1 - 0x10) + size * -0x18;
      local_10 = puVar2 + 2 + size * 3;
      for (i = 0; (ulong)(long)i < size; i = i + 1) {
        __s = strndup((char *)local_10,local_18);
        sLength = strlen(__s);
        local_10 = (ulong *)((long)local_10 + sLength + 1);
        local_18 = (local_18 - sLength) - 1;
        binary = (Binary *)GetBinaryContainingAddress(this,*(ulong *)((long)buffer + (long)i * 8));
        if (binary != (Binary *)0x0) {
          Binary::SetFileName(binary,__s);
        }
      }
      return;
    }
    if ((ulong *)((long)puVar2 + ((ulong)uVar1 + 3 & 0xfffffffffffffffc)) <= local_20 + 3) break;
    *(ulong *)((long)index * 8 + (long)buffer) = *local_20;
    local_20 = local_20 + 3;
    index = index + 1;
  }
  return;
}
```

#### main() continued

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

#### Corefile::GetBacktrace()

The `Corefile::GetBacktrace()` function:
+ initializes `StackWalker` object
+ runs `StackWalker::GetBacktrace()` function
+ runs `Backtrace::GetFrameCount()` function and logs the `frameCount`


#### StackWalker::GetBacktrace()

```cpp
Backtrace * __thiscall StackWalker::GetBacktrace(StackWalker *this, ulong address) {
  /* variables */
  
  backtrace = (Backtrace *)operator.new(0xc0);
  Backtrace::Backtrace(backtrace, address);
  binaryWithAddr = (Binary *)this->corefile.GetBinaryContainingAddress(address);
  tempAddr = address;
  if (binaryWithAddr != (Binary *)0x0) {
    while (isContain = (bool)binaryWithAddr.ContainsVirtualAddress(tempAddr), isContain == true) {
      vAddr = Binary::GetVirtualAddress(binaryWithAddr);
      coreAddr = binaryWithAddr.GetCore();
      addrInCore = *(coreAddr + (tempAddr - vAddr & 0xfffffffffffffff8));
      binaryWithNewAddr = this->corefile.GetBinaryContainingAddress(addrInCore);
      if ((binaryWithNewAddr != (Binary *)0x0) && binaryWithNewAddr.IsExecutable() == true)) {
        backtrace.PushModule(binaryWithNewAddr, addrInCore, tempAddr - address);
      }
      tempAddr = tempAddr + 8;
    }
  }
  return backtrace;
}
```

#### Backtrace::Backtrace()

```cpp
void __thiscall Backtrace::Backtrace(Backtrace *this, ulong address) {
  /* variables */
  
  this->address = address;
  std::optional<unsigned_int>::optional();
  tmpThis = (CallFrame *)this;
  for (offset = 6; tmpThis = (CallFrame *)(tmpThis + 0x18), -1 < offset; offset = offset + -1) {
    CallFrame::CallFrame(tmpThis);
  }
  memset(this->frames, 0, 0xa8);
  return;
}
```

#### Backtrace::PushModule()

```cpp
void __thiscall Backtrace::PushModule(Backtrace *this, Binary *binary, ulong addrInCore, ulong offset) {
  /* variables */
  
  hasValue = this->frameCount.has_value();
  if (hasValue != true) {
    initValue = 1;
    this->frameCount = initValue;
  }
  maxValue = 6;
  if (this->frameCount <= maxValue) {
    frameCount = this->frameCount.value();
    newFrameCount = frameCount + 1;
    this->frameCount = newFrameCount;
    vAddr = binary.GetVirtualAddress();
    currFrame = CallFrame::CallFrame(offset, addrInCore - vAddr, binary);
    frameCount = *this->frameCount;
    frameIdx = frameCount - 1;
    this->frames[frameIdx].field0_0x0 = currFrame.field0_0x0;
    this->frames[frameIdx].field1_0x8 = currFrame.field1_0x8;
    this->frames[frameIdx].binary = currFrame.binary;
  }
  return;
}
```

#### Backtrace::GetFrameCount()

```cpp
uint __thiscall Backtrace::GetFrameCount(Backtrace *this) {
  uint *frameCountPtr;
  
  frameCountPtr = *this->frameCount;
  return *frameCountPtr;
}
```

#### Symbolizer::Symbolicate()

This is probably the most juicy part of the code because of that part:

```cpp
length = snprintf((char *)0x0, 0, "%s --obj=%s %p", "llvm-symbolizer", binaryName, offset);
commandBuf = (char *)malloc((long)(length + 1));
binaryName = binary.GetFileName();
snprintf(commandBuf, length + 1, "%s --obj=%s %p", "llvm-symbolizer", binaryName, offset);
popen(commandBuf, "r");
```

The function inserts the binary name to the command and executes it. We will win if we make `Binary::GetFileName()` return something like this:
`a 0x1; cat /flag #` because the executed command will look like this:
```bash
$ llvm-symbolizer --obj=a 0x1; cat /flag # $offset
```

and the program is later returning to us the output of the function, so flag would be there!

> It is indeed possible to simply overwrite the filename in the _coredump_ file but this is unintended solution, so no fun.
> In order to proceed with the writeup we have to assume the program is validating the filename when parsing _coredump_ file
> for example by checking if the file exists.
{: .prompt-info }

## vulnerabilities

### Corefile::ParseNTFile()

The `Corefile::ParseNTFile()` function calls `malloc(size << 3)` **where `size` is taken directly from _coredump_ file.**
The means we are able to cause `Integer Overflow` here.

```cpp
#include <utility>
#include <string>
#include <vector>
#include <iostream>
#include <optional>


using namespace std;


int main (int argc, char *argv[]) {
    ulong test = 0x2000000000000000;
    printf("0x%lx vs 0x%lx\n", test, test<<3);
    return 0;
}
```
```bash
➜  tests git:(main) ✗ g++ int_overflow.cpp -std=c++17 -o int_overflow
➜  tests git:(main) ✗ ./int_overflow
0x2000000000000000 vs 0x0
```

considering the fact that allocated chunk is later used to copy data from _coredump_ file into it and the size is used to determine
how much data to copy - we have `Heap Overflow` here with ability to overwrite memory with whatever we want (buffer is under our control).

### Backtrace::GetFrameCount()

The function is not vulnerable by it's own. It is the design which can cause vulnerabilities wherever this function is used.
`Backtrace::frameCount` is of type `std::optional<unsigned int>` which means that the value can be uninitialized in some cases.
However, the function `Backtrace::GetFrameCount()` doesn't check whether `std::optional::has_value()`.
In that case, the caller would be responsible for checkig if the value is initialized.

The `frameCount` is fetched in three places:
1. `Backtrace::PushModule()`
```cpp
hasValue = this->frameCount.has_value();
if (hasValue != true) {
  initValue = 1;
  this->frameCount = initValue;
}
```
the function correctly checks if the `frameCount` is initialized with a value. Otherwise, it initializes the `frameCount` with 1.
2. `Corefile::GetBacktrace()`
```cpp
frameCount = Backtrace::GetFrameCount(backtrace);
clog(frameCount);
```
the function doesn't check if the `frameCount` is initialized, nothing interesting as it just logs the value.
3. `main()`
```cpp
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
```
the function doesn't check if the `frameCount` is initialized and gets into a loop where **number of iterations is equal to `frameCount`.**
The `for` loop iterates over `Backtrace::frames` list of `CallFrame` structures.
It then gets the binary address for `CallFrame` structure and passes it to `Symbolizer`.

Ther is only one puzzle missing. How the initialization of `frameCount` is performed:

### Backtrace::Backtrace()

```cpp
void __thiscall Backtrace::Backtrace(Backtrace *this, ulong address) {
  /* variables */
  
  this->address = address;
  std::optional<unsigned_int>::optional(std::nullopt_t);

  /* not important code */
}
```

if basically calls a `std::optional<unsigned_int>` constructor with `std::nullopt_t` without setting the value.
I decided to manually overwrite the memory before initialization of `std::optional` and check what value will `Backtrace::GetFrameCount()` return in main.

1. Set the breakpoint to `Backtrace::Backtrace()` constructor
```bash
pwndbg> b Backtrace::Backtrace(unsigned long) 
Breakpoint 5 at 0x71f8 (2 locations)
```
2. Overwrite the memory
```bash
pwndbg> p/x $rdi # get address of Backtrace object
$1 = 0x562592378e00
pwndbg> set {long}(0x562592378e00+0x10)=0xdeadbeefcafebabe # overwrite the memory
```
3. Compare memory before and after calling constructor
```python
# step until std::optional constructor is called
pwndbg> x/10xg 0x562592378df0
0x562592378df0:	0x000000006f732e31	0x00000000000000d1 # beginning of Backtrace object
0x562592378e00:	0x00007ffc0b3e1d90	0x0000000000000000
0x562592378e10:	0xdeadbeefcafebabe	0x0000000000000000 # overwritten memory
# step out of the constructor
pwndbg> x/10xg 0x562592378df0
0x562592378df0:	0x000000006f732e31	0x00000000000000d1 # beginning of Backtrace object
0x562592378e00:	0x00007ffc0b3e1d90	0x0000000000000000
0x562592378e10:	0xdeadbe00cafebabe	0x0000000000000000 # overwritten memory
0x562592378e20:	0x0000000000000000	0x0000000000000000
0x562592378e30:	0x0000000000000000	0x0000000000000000
```

The bytes at offset 4 was set to `0x00` and nothing more. This is the byte used to determine if the `std::optional` object has a value.

## exploitation

### analysis summary

1. We want to trick the program into executing command with malicious filename but we are not able to simply pass it from _coredump_ file
2. We have heap overflow in `Corefile::ProcessNTFile()`
3. The `Backtrace::GetFrameCount()` can return uninitialized value and the loop in main relies on the value
4. The `Backtrace::PushModule()` function initializes the value of `frameCount`

### idea

1. Abuse the heap overflow in order to overwrite the memory that will later be used for `std::optional`.
2. Initialize the `Backtrace` object
3. Avoid calling `Backtrace::PushModule()` from `StackWalker::GetBacktrace()`

If we manage to execute those steps we will have control over the `frameCount`. It is important to remember where it is used:
```cpp
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
```

```cpp
class Binary {
  uint64_t core;
  uint64_t size;
  char[64] fileName;
  uint64_t virtualAddress;
  uint64_t memoryProtections;
};

class CallFrame {
  uint64_t field0;
  uint64_t field1;
  Binary* binaryAddr;
};

class Backtrace {
  uint64_t address;
  uint64_t field1;
  std::optional<unsigned_int> frameCount;
  CallFrame[6] callFrame;
};
```

If `frameCount` will return value bigger than 6 we would have OOB read. We could abuse that to trick program into reading our fake `CallFrame` object
that would have set `binaryAddr` to fake `Binary` object with malicious filename.


[googlectf]:    https://capturetheflag.withgoogle.com/challenges/pwn-madcore
[madcore_zip]:  https://embe221ed.dev/files/CTFs/GoogleCTF/2022/pwn/madcore/madcore.zip
