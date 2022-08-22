using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.ComponentModel;
using System.Resources;
using System.Reflection;
using System.IO;
using System.Xml.Serialization;
using VirtualSmartCard;
using System.Runtime.InteropServices;

namespace System
{
    public class SmartCard {
        public enum scope : uint
        {
            SCARD_SCOPE_USER = 0,
            SCARD_SCOPE_TERMINAL = 1,
            SCARD_SCOPE_SYSTEM = 2
        };

        public enum share : uint
        {
            SCARD_SHARE_EXCLUSIVE = 1,
            SCARD_SHARE_SHARED = 2,
            SCARD_SHARE_DIRECT = 3
        }

        public enum protocol : uint
        {
            SCARD_PROTOCOL_UNDEFINED = 0x00000000,
            SCARD_PROTOCOL_T0 = 0x00000001,
            SCARD_PROTOCOL_T1 = 0x00000002,
            SCARD_PROTOCOL_T0orT1 = 0x00000003,
            SCARD_PROTOCOL_RAW = 0x00010000
        }

        public enum disposition : uint
        {
            SCARD_LEAVE_CARD = 0,
            SCARD_RESET_CARD = 1,
            SCARD_UNPOWER_CARD = 2,
            SCARD_EJECT_CARD = 3
        }

        static public IntPtr context = IntPtr.Zero;
        public IntPtr cardHandle = IntPtr.Zero;
        [DllImport("winscard.dll", EntryPoint = "SCardConnectA", CharSet = CharSet.Ansi)]
        static extern uint SCardConnect(IntPtr context, String reader, share ShareMode, protocol PreferredProtocols, out IntPtr cardHandle, out protocol ActiveProtocol);
        [DllImport("winscard.dll")]
        static extern uint SCardDisconnect(IntPtr hCard, disposition Disposition);
        [DllImport("winscard.dll")]
        static extern uint SCardGetAttrib(IntPtr hCard, uint AttrId, byte[] Attrib, ref int AttribLen);
        [DllImport("winscard.dll", EntryPoint = "SCardListReadersA", CharSet = CharSet.Ansi)]
        static extern uint SCardListReaders(IntPtr hContext, byte[] mszGroups, byte[] mszReaders, ref UInt32 pcchReaders);
        [DllImport("winscard.dll")]
        static extern uint SCardEstablishContext(scope Scope, IntPtr reserved1, IntPtr reserved2, out IntPtr context);
        [DllImport("winscard.dll")]
        static extern uint SCardIsValidContext(IntPtr context);

        public SmartCard() {
            if (context == IntPtr.Zero || SCardIsValidContext(context) != 0)
                SCardEstablishContext(scope.SCARD_SCOPE_SYSTEM, IntPtr.Zero, IntPtr.Zero, out context);
        }

        public String[] ListReaders()
        {
            string[] readers;
            UInt32 pcchReaders = 0;
            SCardListReaders(context, null, null, ref pcchReaders);
            byte[] mszReaders = new byte[pcchReaders];
            SCardListReaders(context, null, mszReaders, ref pcchReaders);
            System.Text.ASCIIEncoding asc = new System.Text.ASCIIEncoding();
            String[] Readers = asc.GetString(mszReaders).Split('\0');
            if (Readers.Length > 2)
            {
                String[] res = new String[Readers.Length - 2];
                int j = 0;
                for (int i = 0; i < Readers.Length; i++)
                {
                    if (Readers[i] != "" && Readers[i] != null)
                    {
                        res[j] = Readers[i];
                        j++;
                    }
                }
                readers = res;
                return readers;
            }
            else
            {
                readers = new String[0];
                return readers;
            }
        }

        public bool Connect(String reader, share ShareMode, protocol PreferredProtocols)
        {
            protocol activeProtocol;
            uint ris = SCardConnect(context, reader, ShareMode, PreferredProtocols, out cardHandle, out activeProtocol);
            if (ris != 0)
                return false;
            return true;
        }

        public void Disconnect(disposition Disposition)
        {
            if (cardHandle != IntPtr.Zero)
                SCardDisconnect(cardHandle, Disposition);
            cardHandle = IntPtr.Zero;
        }

        public byte[] GetAttrib(uint attrib)
        {
            int AttrLen = 0;
            uint ris = SCardGetAttrib(cardHandle, attrib, null, ref AttrLen);
            if (ris != 0)
                return null;
            byte[] Attr = new byte[AttrLen];
            ris = SCardGetAttrib(cardHandle, attrib, Attr, ref AttrLen);
            if (ris != 0)
                return null;
            return Attr;
        }

    }
    public class ByteArray : ICloneable
    {
        public static string hexDump(byte[] input)
        {
            StringBuilder sbBytes = new StringBuilder(input.Length * 2);
            foreach (byte b in input)
            {
                sbBytes.AppendFormat("{0:X2}", b);
            }
            return sbBytes.ToString();
        }

        public static byte[] parseHex(String hex)
        {
            try
            {
                var data = new List<byte>(hex.Length / 3);
                for (int i = 0; i < hex.Length; i++)
                {
                    if (i == hex.Length - 1)
                    {
                        data.Add(Byte.Parse(hex.Substring(i, 1), System.Globalization.NumberStyles.HexNumber));
                        break;
                    }
                    data.Add(Byte.Parse(hex.Substring(i, 2), System.Globalization.NumberStyles.HexNumber));

                    if ((i + 1) < hex.Length && !Char.IsWhiteSpace(hex[i + 1]))
                        i++;
                    while ((i + 1) < hex.Length && Char.IsWhiteSpace(hex[i + 1]))
                        i++;
                }
                return data.ToArray();
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        public uint ToUInt
        {
            get
            {
                if (data == null)
                    return 0;
                uint val = 0;
                for (int i = 0; i < data.Length; i++)
                    val = (val << 8) | data[i];
                return val;
            }
        }

        public bool IsEqual(byte[] b)
        {
            if ((b == null) != (data == null))
                return false;
            if (data.Length != b.Length)
                return false;
            for (int i = 0; i < data.Length; i++)
                if (data[i] != b[i])
                    return false;

            return true;
        }

        public String ToBase64
        {
            get
            {
                if (data == null)
                    return "";
                return Convert.ToBase64String(data);
            }
        }
        public String ToHex
        {
            get
            {
                if (data == null)
                    return "";
                return ToString();
            }
        }
        public String ToASCII
        {
            get
            {
                if (data == null)
                    return "";
                int index = Array.FindIndex<byte>(data, b => (b == 0));
                if (index >= 0)
                    return ASCIIEncoding.ASCII.GetString(data, 0, index);
                return ASCIIEncoding.ASCII.GetString(data);
            }
        }
        byte[] data;
        public int Size { get { return data != null ? data.Length : 0; } }
        public byte[] Data { get { return data; } }

        public static ByteArray RemoveBT1(ByteArray data)
        {
            if (data[0] != 0)
                throw new Exception("Padding BT1 non valido");
            if (data[1] != 1)
                throw new Exception("Padding BT1 non valido");
            int i = 0;
            for (i = 2; i < data.Size - 1; i++)
            {
                if (data[i] != 0xff)
                {
                    if (data[i] != 0x00)
                        throw new Exception("Padding BT1 non valido");
                    else
                        break;
                }
            }
            return data.Sub(i + 1);
        }
        public static ByteArray Fill(int size, byte content)
        {
            byte[] data = new byte[size];
            for (int i = 0; i < size; i++)
                data[i] = content;
            return data;
        }
        public static ByteArray RemoveISOPad(byte[] data)
        {
            int i;
            for (i = data.Length - 1; i >= 0; i--)
            {
                if (data[i] == 0x80)
                    break;
                if (data[i] != 0)
                    throw new Exception("Padding ISO non presente");
            }
            return new ByteArray(data).Left(i);
        }


        public static ByteArray BT1Pad(ByteArray data, int lenght)
        {
            if (data.Size > (lenght - 3))
                throw new Exception("Dati da paddare troppo lunghi");
            return new ByteArray(new byte[] { 0, 1 }).Append(ByteArray.Fill(lenght - data.Size - 3, 0xff)).Append(0).Append(data);
        }
        public static ByteArray ANSIPad(byte[] data)
        {
            int padLen;
            if ((data.Length & 0x7) == 0)
                padLen = data.Length;
            else
                padLen = data.Length - (data.Length & 0x7) + 0x08;

            byte[] padData = new byte[padLen];
            data.CopyTo(padData, 0);
            for (int i = data.Length; i < padData.Length; i++)
                padData[i] = 0;
            return padData;
        }

        public static ByteArray ISOPad(byte[] data)
        {
            int padLen;
            if ((data.Length & 0x7) == 0)
                padLen = data.Length + 8;
            else
                padLen = data.Length - (data.Length & 0x7) + 0x08;

            byte[] padData = new byte[padLen];
            data.CopyTo(padData, 0);
            padData[data.Length] = 0x80;
            for (int i = data.Length + 1; i < padData.Length; i++)
                padData[i] = 0;
            return padData;
        }

        static System.Random rnd = new Random();
        public void Random(int size)
        {
            data = new byte[size];
            rnd.NextBytes(data);
        }
        public ByteArray Left(int num)
        {
            if (num > this.data.Length)
                return this.Clone() as ByteArray;
            byte[] data = new byte[num];
            Array.Copy(this.data, data, num);
            return data;
        }

        public ByteArray Reverse()
        {
            ByteArray rev = data.Clone() as byte[];
            Array.Reverse(rev.data);
            return rev;
        }

        public ByteArray Sub(int start, int num)
        {
            byte[] data = new byte[num];
            Array.Copy(this.data, start, data, 0, num);
            return data;
        }

        public ByteArray Sub(int start)
        {
            byte[] data = new byte[this.data.Length - start];
            Array.Copy(this.data, start, data, 0, data.Length);
            return data;
        }

        public ByteArray Right(int num)
        {
            if (num > this.data.Length)
                return this.Clone() as ByteArray;
            byte[] data = new byte[num];
            Array.Copy(this.data, this.data.Length - num, data, 0, num);
            return data;
        }
        static byte[] tagToBytes(ulong value)
        {
            if (value <= 0xff)
            {
                return new byte[] { (byte)value };
            }
            else if (value <= 0xffff)
            {
                return new byte[] { (byte)(value >> 8), (byte)(value & 0xff) };
            }
            else if (value <= 0xffffff)
            {
                return new byte[] { (byte)(value >> 16), (byte)((value >> 8) & 0xff), (byte)(value & 0xff) };
            }
            else if (value <= 0xffffffff)
            {
                return new byte[] { (byte)(value >> 24), (byte)((value >> 16) & 0xff), (byte)((value >> 8) & 0xff), (byte)(value & 0xff) };
            }
            throw new Exception("tag troppo lungo");
        }
        static byte[] lenToBytes(ulong value)
        {
            if (value < 0x80)
            {
                return new byte[] { (byte)value };
            }
            if (value <= 0xff)
            {
                return new byte[] { 0x81, (byte)value };
            }
            else if (value <= 0xffff)
            {
                return new byte[] { 0x82, (byte)(value >> 8), (byte)(value & 0xff) };
            }
            else if (value <= 0xffffff)
            {
                return new byte[] { 0x83, (byte)(value >> 16), (byte)((value >> 8) & 0xff), (byte)(value & 0xff) };
            }
            else if (value <= 0xffffffff)
            {
                return new byte[] { 0x84, (byte)(value >> 24), (byte)((value >> 16) & 0xff), (byte)((value >> 8) & 0xff), (byte)(value & 0xff) };
            }
            throw new Exception("dati troppo lunghi");
        }
        public ByteArray ASN1Tag(ulong tag)
        {
            byte[] _tag = tagToBytes(tag);
            byte[] _len = lenToBytes((ulong)this.data.Length);
            byte[] data = new byte[_tag.Length + _len.Length + this.data.Length];
            Array.Copy(_tag, 0, data, 0, _tag.Length);
            Array.Copy(_len, 0, data, _tag.Length, _len.Length);
            Array.Copy(this.data, 0, data, _tag.Length + _len.Length, this.data.Length);
            return data;
        }

        public ByteArray Append(String data)
        {
            return Append(new ByteArray(data));
        }

        public ByteArray Append(byte data)
        {
            return Append(new byte[] { data });
        }
        public byte this[int i]
        {
            get { return data[i]; }
            set { data[i] = value; }
        }
        public ByteArray Append(ByteArray data)
        {
            if (data == null)
                return Clone() as ByteArray;
            return Append(data.data);
        }
        public ByteArray Append(byte[] data)
        {
            if (data == null)
            {
                if (this.data == null)
                    return new ByteArray();
                else
                    return this.data.Clone() as byte[];
            }
            else if (this.data == null)
                return data.Clone() as byte[];
            byte[] newData = new byte[data.Length + this.data.Length];
            this.data.CopyTo(newData, 0);
            data.CopyTo(newData, this.data.Length);
            return newData;
        }

        public static implicit operator ByteArray(String str)
        {
            return new ByteArray(str);
        }
        public static implicit operator ByteArray(Byte[] ba)
        {
            return new ByteArray(ba);
        }

        static public ByteArray FromASCII(String data)
        {
            return ASCIIEncoding.ASCII.GetBytes(data);
        }
        public ByteArray() { }
        public ByteArray(byte data)
        {
            this.data = new byte[] { data };
        }
        public bool CompareByteArray(byte[] data) {
            if ((this.data==null)!=(data==null))
                return false;
            if (data == null)
                return true;
            if (data.Length != this.data.Length)
                return false;
            for (int i = 0; i < data.Length; i++) {
                if (data[i] != this.data[i])
                    return false;
            }
            return true;
        }
        public ByteArray(byte[] data)
        {
            this.data = data;
        }
        public ByteArray(string hexData)
        {
            data = readHexData(hexData);
        }

        public static implicit operator byte[](ByteArray ba)
        {
            return ba.data;
        }

        public static implicit operator MemoryStream(ByteArray ba)
        {
            return new MemoryStream(ba.data);
        }

        static byte hex2byte(char h)
        {
            if (h >= '0' && h <= '9') return (byte)(h - '0');
            if (h >= 'A' && h <= 'F') return (byte)(h + 10 - 'A');
            if (h >= 'a' && h <= 'f') return (byte)(h + 10 - 'a');
            return 0;
        }

        static bool IsHexDigit(char c)
        {
            if (c >= '0' && c <= '9') return true;
            if (c >= 'a' && c <= 'f') return true;
            if (c >= 'A' && c <= 'F') return true;
            return false;
        }
        public override string ToString()
        {
            if (data == null)
                return "";
            StringBuilder sb = new StringBuilder(data.Length * 3);
            for (int i = 0; i < data.Length; i++)
                sb.Append(data[i].ToString("X02") + " ");
            return sb.ToString();
        }
        public static byte[] readHexData(String data)
        {
            List<byte> dt = new List<byte>();

            int slen = data.Length;
            for (int i = 0; i < slen; i++)
            {
                Char c = data[i];
                if (Char.IsWhiteSpace(c) || c == ',') continue;
                if (!IsHexDigit(c))
                {
                    throw new Exception("Carattere non valido:" + c);
                }

                if ((i < slen - 3) && c == '0' && data[i + 3] == 'h')
                    continue;

                if ((i < slen - 2) && c == '0' && data[i + 1] == 'x')
                {
                    i += 1;
                    continue;
                }
                byte v = hex2byte(c);
                i++;
                Char d = data[i];
                if (i < slen)
                {
                    if (IsHexDigit(d))
                    {
                        v <<= 4;
                        v |= hex2byte(d);
                    }
                    else if (!Char.IsWhiteSpace(d))
                        throw new Exception("richiesto spazio");
                }
                dt.Add(v);

                if (i < (slen - 1) && data[i + 1] == 'h')
                    i++;
            }
            return dt.ToArray();
        }

        #region ICloneable Members

        public object Clone()
        {
            return new ByteArray((byte[])data.Clone());
        }

        #endregion
    }

    public class Util {

        public static byte[] Response(byte[] data, int offset,int len,ushort sw)
        {
            if (data.Length < len)
                return Response(data, sw);
            byte[] resp = new byte[len + 2];
            Array.Copy(data, offset, resp, 0, len);
            resp[len] = UpperByte(sw);
            resp[len + 1] = LowerByte(sw);
            return resp;
        }
        
        public static byte[] Response(byte[] data, ushort sw)
        {
            if (data == null)
                return ToByteArray(sw);
            
            byte[] resp = new byte[data.Length + 2];
            data.CopyTo(resp, 0);
            resp[data.Length] = UpperByte(sw);
            resp[data.Length + 1] = LowerByte(sw);
            return resp;
        }
        public static byte[] ToByteArray(ushort id) {
            return new byte[] { (byte)(id >> 8), (byte)(id & 0xff) };
        }

        public static ushort ToUShort(byte[] bytes, int offset)
        {
            if (bytes.Length <= offset)
                return 0;
            if (bytes.Length == offset + 1)
                return bytes[offset];
            return (ushort)(bytes[offset] << 8 | bytes[offset + 1]);
        }

        public static uint ToUInt(params byte[] bytes)
        {
            uint tot=0;
            if (bytes.Length == 0)
                return 0;
            foreach (var v in bytes)
                tot = (tot << 8) | v;
            return tot;
        }

        public static ushort ToUShort(params byte[] bytes)
        {
            if (bytes.Length == 0)
                return 0;
            if (bytes.Length == 1)
                return bytes[0];
            return (ushort)(bytes[bytes.Length - 2] << 8 | bytes[bytes.Length - 1]);
        }

        public static byte UpperByte(ushort id)
        {
            return (byte)(id >> 8);
        }

        public static byte LowerByte(ushort id)
        {
            return (byte)(id & 0xff);
        }

        public static bool CompareByteArray(byte[] d1, byte[] d2) {
            return new ByteArray(d1).CompareByteArray(d2);
        }
    }
}
