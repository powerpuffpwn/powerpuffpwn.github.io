---
title: BSidesSF 2021 Secure Asset Manager 
updated: 2021-04-03 00:00
category: writeup
tags: pwn
author: h0ng10
---

### Secure Asset Manager

We are provided with a stripped x64 binary, so no symbols there:

```
> file secure-asset-manager
secure-asset-manager: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=848cdd37427cba3d8263e58fda3ba117db2157ec, stripped
```

When you run the binary you are not prompted for any input. The binary simply connects to an external service and "does stuff". We don't have access to the server side component.

A good way to get a basic overview is to execute the binary via "strace". The following snippet shows the interesting parts:

```
...
socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 4
setsockopt(4, SOL_IP, IP_RECVERR, [1], 4) = 0
connect(4, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, 16) = 0
poll([{fd=4, events=POLLOUT}], 1, 0)    = 1 ([{fd=4, revents=POLLOUT}])
sendto(4, "\317\t\1 \0\1\0\0\0\0\0\1\35secure-asset-manage"..., 82, MSG_NOSIGNAL, NULL, 0) = 82
poll([{fd=4, events=POLLIN}], 1, 5000)  = 1 ([{fd=4, revents=POLLIN}])
ioctl(4, FIONREAD, [98])                = 0
recvfrom(4, "\317\t\201\200\0\1\0\1\0\0\0\1\35secure-asset-manage"..., 1024, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, [28->16]) = 98
close(4)                                = 0
connect(3, {sa_family=AF_INET, sin_port=htons(6112), sin_addr=inet_addr("35.233.170.150")}, 16) = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0), ...}) = 0
write(1, "Connected to secure-asset-manage"..., 72Connected to secure-asset-manager-4235c8a4.challenges.bsidessf.net:6112
) = 72
read(3, "\"\0", 2)                      = 2
read(3, "secure-asset-manager server v1.0"..., 34) = 34
write(1, "Server version: secure-asset-man"..., 50Server version: secure-asset-manager server v1.00
) = 50
write(3, "\"\0", 2)                     = 2
write(3, "secure-asset-manager client v1.0"..., 34) = 34
read(3, "\250\0", 2)                    = 2
read(3, "\271o\26x\312H9\367\17\215\227\0\0\0\213\7H\203\307\4-\20\3374\266\301\310\24-\264\251\227"..., 168) = 168
write(1, "Received server challenge (168 b"..., 60Received server challenge (168 bytes), calculating response
) = 60
openat(AT_FDCWD, "/proc/self/maps", O_RDONLY) = 4
fstat(4, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0
read(4, "56244e1ff000-56244e200000 r--p 0"..., 1024) = 1024
read(4, "00 fd:00 1971874                "..., 1024) = 1024
read(4, "/usr/lib/x86_64-linux-gnu/libnss"..., 1024) = 1024
read(4, "ibc-2.31.so\n7f9228a52000-7f9228a"..., 1024) = 1024
read(4, "sr/lib/x86_64-linux-gnu/ld-2.31."..., 1024) = 409
read(4, "", 1024)                       = 0
close(4)                                = 0
mmap(NULL, 168, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANONYMOUS, -1, 0) = 0x7f9228ae0000
munmap(0x7f9228ae0000, 168)             = 0
write(1, "Sending challenge response\n", 27Sending challenge response
) = 27
write(3, "\4\0", 2)                     = 2
write(3, "\2377\276\307", 4)            = 4
read(3, "\4\0", 2)                      = 2
read(3, "PASS", 4)                      = 4
write(1, "Server challenge passed!\n", 25Server challenge passed!
) = 25
write(1, "Checking for updates...\n", 24Checking for updates...
) = 24
write(3, "\16\0", 2)                    = 2
write(3, "CHECK_UPDATES\0", 14)         = 14
read(3, "\32\0", 2)                     = 2
read(3, "0 :: No updates available\0", 26) = 26
write(1, "No updates available!\n", 22No updates available!
) = 22
uname({sysname="Linux", nodename="develop", ...}) = 0
write(1, "Checking in with hostname...\n", 29Checking in with hostname...
) = 29
write(3, "\r\0", 2)                     = 2
write(3, "I_AM develop\0", 13)          = 13
read(3, "7\0", 2)                       = 2
read(3, "OK :: Checkin successful! For mo"..., 55) = 55
write(1, "Check-in successful! Thanks for "..., 74Check-in successful! Thanks for using secure-asset-manager client v1.00!!
) = 74
write(1, "Disconnecting...\n", 17Disconnecting...
)      = 17
write(3, "\4\0", 2)                     = 2
write(3, "BYE\0", 4)                    = 4
close(3)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

We can see that the challenge uses a simple length-value protocol. First the length of the command is written, followed by the actual command. :
```
write(3, "\16\0", 2)                    = 2
write(3, "CHECK_UPDATES\0", 14)         = 14
```

We can also see that the client does something odd when calculating the challenge response. It seems to access its own memory (via /proc/self/maps). Additionally it creates a new memory region with read-write-exec permissions, which gets deleted afterwards:

```
write(1, "Received server challenge (168 b"..., 60Received server challenge (168 bytes), calculating response
) = 60
openat(AT_FDCWD, "/proc/self/maps", O_RDONLY) = 4
fstat(4, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0
read(4, "56244e1ff000-56244e200000 r--p 0"..., 1024) = 1024
read(4, "00 fd:00 1971874                "..., 1024) = 1024
read(4, "/usr/lib/x86_64-linux-gnu/libnss"..., 1024) = 1024
read(4, "ibc-2.31.so\n7f9228a52000-7f9228a"..., 1024) = 1024
read(4, "sr/lib/x86_64-linux-gnu/ld-2.31."..., 1024) = 409
read(4, "", 1024)                       = 0
close(4)                                = 0
mmap(NULL, 168, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANONYMOUS, -1, 0) = 0x7f9228ae0000
munmap(0x7f9228ae0000, 168)             = 0
write(1, "Sending challenge response\n", 27Sending challenge response
) = 27
```

### Analyzing the server challenge

I then reversed the binary to analyze the way how the "server challenge" is resolved. In a nutshell, it works as follows:

1. Locate the code segment of the binary (using /proc/self/maps)
2. Execute some (server provided) random assembly code on the dump
3. Return the result
4. The server compares the result with his own calculation (the server must therefore also have a copy of the binary)

This creates a problem for us if we want to create a custom client or modify the binary itself as this would use a different code segment. Even setting a break point in the debugger will cause the challenge to fail (because the debugger modifies the code on the fly).

So we basically have two options to solve the challenge:

1. We can create our own client. In this case we need a way to solve the challenge that will be provided by the server. We can dump the memory from an unmodified client and use this dump to calculate the result.
2. We create a proxy that intercepts the communication between the original client and the server. The unmodified client will solve the challenge for us, however we can modify the commands that will be send to the service afterwards.

I decided to take the second approach as this could be implemented more easily with James Forshows [Canape](https://github.com/tyranid/canape). I already had some experience with the GUI version. However I used the challenge to get some experience with [CANAPE.Core](https://github.com/tyranid/CANAPE.Core), the program library.

### Solving the challenge with a proxy
James Forshaw wrote a great book about [attacking network protocols](https://nostarch.com/networkprotocols). I used the sources from the NoStarch site to get an initial template for CANAPE.core that I can build on.

The following code shows the "parser.csx" file, which is basically responsible for reading the length (as short value) and then getting the actual command into our frame:

```
using CANAPE.Net.Layers;
using System.IO;
using System.Text;

class Parser : DataParserNetworkLayer
{
    protected override bool NegotiateProtocol(Stream outboundStream, Stream inboundStream)
    {
        // Read magic.
        var reader = new DataReader(inboundStream);
        var writer = new DataWriter(outboundStream);

        return true;
    }

    DataFrame ReadData(DataReader reader) {
        UInt16 length = reader.ReadUInt16(true);
        DataFrame frame =  reader.ReadBytes(length).ToDataFrame();
        return frame;
    }

    void WriteData(DataFrame frame, DataWriter writer) {
        
        byte[] data = frame.ToArray();
        ushort length = (ushort) data.Length;
        writer.WriteUInt16(length, true);
        writer.WriteBytes(data);
    }

    protected override DataFrame ReadInbound(DataReader reader)
    {
        return ReadData(reader);
    }

    protected override void WriteOutbound(DataFrame frame, DataWriter writer)
    {
        
        WriteData(frame, writer);
    }

    protected override DataFrame ReadOutbound(DataReader reader)
    {
        DataFrame frame = ReadData(reader);
        return frame;
    }

    protected override void WriteInbound(DataFrame frame, DataWriter writer)
    {
        WriteData(frame, writer);
    }
}
```

The parser.csx file will be included in the main script. The script will start a fixed proxy on port 6112 and forward all incoming packets (after parsing/modifcation) to the actual service. To make this work you need to modify your "/etc/hosts" file, so that the hostname "secure-asset-manager-4235c8a4.challenges.bsidessf.net" is resolved to "localhost".

The code also contains an "EditPacket" event, which simply searches for the "CHECK_UPDATE" command. If found, it is replaces the command with "FLAG":

```
#load "parser.csx"

using static System.Console;
using static CANAPE.Cli.ConsoleUtils;

void EditPacket(object sender, EditPacketEventArgs args) {
    if (args.Tag == "Out") {
        // Edit packet outbound
        // Replace the "CHECK_UPDATES" command with "FLAG"
        string data = args.Frame.ToDataString();
        data = data.Replace("CHECK_UPDATES", "FLAG");
        args.Frame = data.ToDataFrame();
    } 
}

var template = new FixedProxyTemplate();
template.LocalPort = 6112;
template.Host = "35.233.170.150";
template.Port = 6112;
template.AddLayer<Parser>();

var service = template.Create();
// Add an event handler for when a packet is logged. Just print to console.
service.LogPacketEvent += (s,e) => WritePacket(e.Packet); 
// Print to console when a connection is created or closed.
service.NewConnectionEvent += (s,e) => WriteLine("New Connection: {0}", e.Description);
service.CloseConnectionEvent += (s,e) => WriteLine("Closed Connection: {0}", e.Description);
// Add an event handler to edit a packet as it's in the proxy.
service.EditPacketEvent += EditPacket;
service.Start();

WriteLine("Created {0}", service);
WriteLine("Press Enter to exit...");
ReadLine();
service.Stop();
```

If we now run the binary through our proxy, we get the flag inside the network stream from the proxy

```
Time 4/2/2021 6:00:22 AM - Tag 'In' - Network '127.0.0.1:56612 <=> 35.233.170.150:6112'
        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F - 0123456789ABCDEF
--------:-------------------------------------------------------------------
00000000: 50 41 53 53                                     - PASS



Time 4/2/2021 6:00:22 AM - Tag 'Out' - Network '127.0.0.1:56612 <=> 35.233.170.150:6112'
FLAG


Time 4/2/2021 6:00:22 AM - Tag 'In' - Network '127.0.0.1:56612 <=> 35.233.170.150:6112'
        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F - 0123456789ABCDEF
--------:-------------------------------------------------------------------
00000000: 4F 4B 20 3A 3A 20 43 54 46 7B 74 68 69 73 5F 69 - OK :: CTF{this_i
00000010: 73 5F 6B 69 6E 64 61 5F 6C 69 6B 65 5F 74 68 65 - s_kinda_like_the
00000020: 5F 73 74 61 72 63 72 61 66 74 5F 6C 6F 67 69 6E - _starcraft_login
00000030: 7D 00    
```




