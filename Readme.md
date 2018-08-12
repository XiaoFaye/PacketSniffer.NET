PacketSniffer.NET
======================

A Brief Intro
-------------------

PacketSniffer.NET is a .NET Core application for Network Packet Sniffering which will work on Windows, Linux and MacOS.

Usage
-------------------
1. Install the dotnet core 2.0 from https://www.microsoft.com/net/core
2. Clone this repo
3. Navigate to the project folder you prefer
4. If you are running on Linux or macOS, run `gcc -shared -fPIC packetsniffer.c -o packetsniffer.so` first
5. If you are running under macOS, make sure you pass the correct interface name in line 66 of Programe.cs
6. Run `dotnet run` as Administrator or as root
7. You can filter the packets in DataArrival function