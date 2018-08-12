using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace PacketSnifferNET
{
    [StructLayout(LayoutKind.Explicit)]
    public struct IPHeader
    {
        [FieldOffset(0)] public byte ip_verlen;
        [FieldOffset(1)] public byte ip_tos;
        [FieldOffset(2)] public ushort ip_totallength;
        [FieldOffset(4)] public ushort ip_id;
        [FieldOffset(6)] public ushort ip_offset;
        [FieldOffset(8)] public byte ip_ttl;
        [FieldOffset(9)] public byte ip_protocol;
        [FieldOffset(10)] public ushort ip_checksum;
        [FieldOffset(12)] public uint ip_srcaddr;
        [FieldOffset(16)] public uint ip_destaddr;
    }

    public static class OperatingSystem
    {
        public static bool IsWindows() =>
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        public static bool IsMacOS() =>
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

        public static bool IsLinux() =>
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
    }

    public class RawSocket
    {
        private bool error_occurred;
        public bool KeepRunning;
        private static int len_receive_buf;
        byte[] receive_buf_bytes;
        private Socket socket = null;
        const int SIO_RCVALL = unchecked((int)0x98000001);
        const int ETH_P_ALL = 0x0003;

        public class PacketArrivedEventArgs : EventArgs
        {
            public PacketArrivedEventArgs()
            {
                this.protocol = "";
                this.destination_port = "";
                this.origination_port = "";
                this.destination_address = "";
                this.origination_address = "";
                this.ip_version = "";

                this.total_packet_length = 0;
                this.message_length = 0;
                this.header_length = 0;

                this.receive_buf_bytes = new byte[len_receive_buf];
                this.ip_header_bytes = new byte[len_receive_buf];
                this.message_bytes = new byte[len_receive_buf];
            }

            public string Protocol
            {
                get { return protocol; }
                set { protocol = value; }
            }
            public string DestinationPort
            {
                get { return destination_port; }
                set { destination_port = value; }
            }
            public string OriginationPort
            {
                get { return origination_port; }
                set { origination_port = value; }
            }
            public string DestinationAddress
            {
                get { return destination_address; }
                set { destination_address = value; }
            }
            public string OriginationAddress
            {
                get { return origination_address; }
                set { origination_address = value; }
            }
            public string IPVersion
            {
                get { return ip_version; }
                set { ip_version = value; }
            }
            public uint PacketLength
            {
                get { return total_packet_length; }
                set { total_packet_length = value; }
            }
            public uint MessageLength
            {
                get { return message_length; }
                set { message_length = value; }
            }
            public uint HeaderLength
            {
                get { return header_length; }
                set { header_length = value; }
            }
            public byte[] ReceiveBuffer
            {
                get { return receive_buf_bytes; }
                set { receive_buf_bytes = value; }
            }
            public byte[] IPHeaderBuffer
            {
                get { return ip_header_bytes; }
                set { ip_header_bytes = value; }
            }
            public byte[] MessageBuffer
            {
                get { return message_bytes; }
                set { message_bytes = value; }
            }
            private string protocol;
            private string destination_port;
            private string origination_port;
            private string destination_address;
            private string origination_address;
            private string ip_version;
            private uint total_packet_length;
            private uint message_length;
            private uint header_length;
            private byte[] receive_buf_bytes = null;
            private byte[] ip_header_bytes = null;
            private byte[] message_bytes = null;
        }

        public event PacketArrivedEventHandler PacketArrival;
        public delegate void PacketArrivedEventHandler(Object sender, PacketArrivedEventArgs args);

        protected virtual void OnPacketArrival(PacketArrivedEventArgs e)
        {
            PacketArrival?.Invoke(this, e);
        }

        /// <summary>
        /// Raw Socket Constructor
        /// </summary>
        public RawSocket()
        {
            error_occurred = false;
            len_receive_buf = 4096;
            receive_buf_bytes = new byte[len_receive_buf];
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="IP"></param>
        /// <param name="port"></param>
        /// <param name="protocal"></param>
        public void CreateAndBindSocket(string IP, int port = 0, ProtocolType protocal = ProtocolType.IP)
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, protocal);

            socket.Blocking = false;
            socket.Bind(new IPEndPoint(IPAddress.Parse(IP), port));

            if (SetSocketOption() == false) error_occurred = true;
        }

        private bool SetSocketOption()
        {
            bool ret_value = true;
            try
            {
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, 1);

                byte[] IN = new byte[4] { 1, 0, 0, 0 };
                byte[] OUT = new byte[4];


                int ret_code = socket.IOControl(SIO_RCVALL, IN, OUT);
                ret_code = OUT[0] + OUT[1] + OUT[2] + OUT[3];
                if (ret_code != 0) ret_value = false;
            }
            catch (SocketException)
            {
                ret_value = false;
            }
            return ret_value;
        }

        public bool ErrorOccurred
        {
            get
            {
                return error_occurred;
            }
        }

        unsafe private void Receive(byte[] buf, int len)
        {
            byte temp_protocol = 0;
            uint temp_version = 0;
            uint temp_ip_srcaddr = 0;
            uint temp_ip_destaddr = 0;
            short temp_srcport = 0;
            short temp_dstport = 0;
            IPAddress temp_ip;

            PacketArrivedEventArgs e = new PacketArrivedEventArgs();

            fixed (byte* fixed_buf = buf)
            {
                IPHeader* head = (IPHeader*)fixed_buf;
                e.HeaderLength = (uint)(head->ip_verlen & 0x0F) << 2;

                //Extract Network Protocal Type
                temp_protocol = head->ip_protocol;
                switch (temp_protocol)
                {
                    case 1: e.Protocol = "ICMP"; break;
                    case 2: e.Protocol = "IGMP"; break;
                    case 6: e.Protocol = "TCP"; break;
                    case 17: e.Protocol = "UDP"; break;
                    default: e.Protocol = "UNKNOWN"; break;
                }

                //Extract Network Protocal Version
                temp_version = (uint)(head->ip_verlen & 0xF0) >> 4;
                e.IPVersion = temp_version.ToString();


                temp_ip_srcaddr = head->ip_srcaddr;
                temp_ip_destaddr = head->ip_destaddr;
                temp_ip = new IPAddress(temp_ip_srcaddr);
                e.OriginationAddress = temp_ip.ToString();
                temp_ip = new IPAddress(temp_ip_destaddr);
                e.DestinationAddress = temp_ip.ToString();

                temp_srcport = *(short*)&fixed_buf[e.HeaderLength];
                temp_dstport = *(short*)&fixed_buf[e.HeaderLength + 2];
                e.OriginationPort = IPAddress.NetworkToHostOrder(temp_srcport).ToString();
                e.DestinationPort = IPAddress.NetworkToHostOrder(temp_dstport).ToString();

                e.PacketLength = (uint)len;
                e.MessageLength = (uint)len - e.HeaderLength;

                e.ReceiveBuffer = buf;

                Array.Copy(buf, 0, e.IPHeaderBuffer, 0, (int)e.HeaderLength);

                Array.Copy(buf, (int)e.HeaderLength, e.MessageBuffer, 0, (int)e.MessageLength);
            }

            OnPacketArrival(e);
        }

        //Start sniffering
        public void Run()
        {
            IAsyncResult ar = socket.BeginReceive(receive_buf_bytes, 0, len_receive_buf, SocketFlags.None, new AsyncCallback(CallReceive), this);
        }

        //Async Callback
        private void CallReceive(IAsyncResult ar)
        {
            int received_bytes;
            try
            {
                received_bytes = socket.EndReceive(ar);
            }
            catch (Exception ex)
            {
                received_bytes = receive_buf_bytes.Length;
            }

            Receive(receive_buf_bytes, received_bytes);
            if (KeepRunning) Run();
        }

        //Shutdown Raw Socket
        public void Shutdown()
        {
            if (socket != null)
            {
                if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                    socket.Shutdown(SocketShutdown.Both);

                socket.Close();
            }
        }
    }
}
