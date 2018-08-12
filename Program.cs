using System;
using System.Net;
using System.Runtime.InteropServices;

namespace PacketSnifferNET
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct PacketData
    {
        public int length;
        public int s_port;
        public int d_port;

        [MarshalAs(UnmanagedType.LPStr)]
        public string protocal;

        [MarshalAs(UnmanagedType.LPStr)]
        public string s_addr;

        [MarshalAs(UnmanagedType.LPStr)]
        public string d_addr;
    }

    class Program
    {
        [DllImport(@"packetsniffer.so", EntryPoint = "capture", CallingConvention = CallingConvention.StdCall)]
        public static extern int capture(string iface, [MarshalAs(UnmanagedType.FunctionPtr)]CallbackFun callback_f);

        public delegate void CallbackFun(IntPtr data);

        static void CSCallbackFun(IntPtr data)
        {
            PacketData p = (PacketData)Marshal.PtrToStructure(data, typeof(PacketData));
            RawSocket.PacketArrivedEventArgs args = new RawSocket.PacketArrivedEventArgs();
            args.MessageLength = (uint)p.length;
            args.Protocol = p.protocal;
            args.OriginationPort = p.s_port.ToString();
            args.DestinationPort = p.d_port.ToString();
            args.OriginationAddress = p.s_addr;
            args.DestinationAddress = p.d_addr;
            args.IPVersion = "IPv4";

            DataArrival(null, args);
        }

        static void Main(string[] args)
        {
            if (OperatingSystem.IsWindows())
            {
                string IPString = "192.168.50.161";

                var myRawSock = new RawSocket();
                myRawSock.CreateAndBindSocket(IPString);
                myRawSock.PacketArrival += new RawSocket.PacketArrivedEventHandler(DataArrival);

                myRawSock.KeepRunning = true;
                myRawSock.Run();

                Console.ReadLine();

                myRawSock.Shutdown();
            }
            else
            {
                //If your are running under macOS, make sure you pass the correct interface name.
                capture("en0", CSCallbackFun);
            }
        }

        private static void DataArrival(Object sender, RawSocket.PacketArrivedEventArgs e)
        {
            if (e.Protocol.ToUpper() == "TCP")
                Console.WriteLine(e.OriginationAddress + " - " + e.OriginationPort + " - " + e.DestinationAddress + " - " + e.DestinationPort + " - " + e.Protocol + " - " + e.PacketLength + " - " + e.HeaderLength + " - " + e.IPVersion);
        }
    }
}
