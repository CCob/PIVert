using System;

namespace ISO7816 {
    public class Apdu
    {
        public Byte INS;
        public Byte CLA;
        public Byte P1;
        public Byte P2;
        public byte[] Data;
        public Byte LE;
        public bool UseLE;

        public byte[] SMRandom;
        public byte[] SMEncKeyOut;
        public byte[] SMSigKeyOut;

        public Apdu()
        {
        }

        public Apdu(byte[] data)
        {
            CLA = data[0];
            INS = data[1];
            P1 = data[2];
            P2 = data[3];
            if (data.Length == 4) {
                this.Data = null;
                UseLE = false;
                return;
            }

            if (data.Length == 5)
            {
                this.Data = null;
                UseLE = true;
                LE = data[4];
                return;
            }

            if (data.Length == 5 + data[4])
            {
                this.Data = new byte[data[4]];
                UseLE = false;
                Array.Copy(data, 5, Data, 0, data[4]);
                return;
            }

            if (data.Length == 6 + data[4])
            {
                this.Data = new byte[data[4]];
                UseLE = true;
                Array.Copy(data, 5, Data, 0, data[4]);
                LE = data[data.Length - 1];
                return;
            }
        }

        public Apdu(Byte _CLA, Byte _INS, Byte _P1, Byte _P2, byte[] _Data, Byte _LE)
        {
            INS = _INS;
            CLA = _CLA;
            P1 = _P1;
            P2 = _P2;
            Data = _Data;
            LE = _LE;
            UseLE = true;
        }

        public Apdu(Byte _CLA, Byte _INS, Byte _P1, Byte _P2, byte[] _Data)
        {
            INS = _INS;
            CLA = _CLA;
            P1 = _P1;
            P2 = _P2;
            Data = _Data;
            LE = 0;
            UseLE = false;
        }

        public Apdu(Byte _CLA, Byte _INS, Byte _P1, Byte _P2, Byte _LE)
        {
            INS = _INS;
            CLA = _CLA;
            P1 = _P1;
            P2 = _P2;
            Data = null;
            LE = _LE;
            UseLE = true;
        }
        public Apdu(Byte _CLA, Byte _INS, Byte _P1, Byte _P2)
        {
            INS = _INS;
            CLA = _CLA;
            P1 = _P1;
            P2 = _P2;
            LE = 0;
            Data = null;
            UseLE = false;
        }

        public static bool IsRespOK(byte[] resp)
        {
            if (resp == null)
                return false;
            if (resp.Length < 2)
                return false;
            if (resp[resp.Length - 2] != 0x90 ||
                resp[resp.Length - 1] != 0x00)
                return false;
            return true;
        }

        public bool IsSM { get { return (CLA & 0x0c) != 0; } }

        public override string ToString()
        {
            String txt;
                txt = String.Format("{0:X2} {1:X2} {2:X2} {3:X2} ", CLA, INS, P1, P2);
            if (Data != null)
            {
                txt += Data.Length.ToString("X2") + " ";
                foreach (byte b in Data)
                {
                    txt += b.ToString("X2");
                }
                txt += " ";
            }
            if (UseLE)
                txt += LE.ToString("X2");
            return txt;
        }

        public byte[] GetBytes()
        {
            int iAPDUSize = 4;
            if (Data != null)
                iAPDUSize += Data.Length + 1;
            if (UseLE)
                iAPDUSize++;

            byte[] pbtAPDU = new byte[iAPDUSize];
            pbtAPDU[0] = CLA;
            pbtAPDU[1] = INS;
            pbtAPDU[2] = P1;
            pbtAPDU[3] = P2;
            if (Data != null && UseLE)
            {
                pbtAPDU[4] = (byte)Data.Length;
                Data.CopyTo(pbtAPDU, 5);
                pbtAPDU[5 + Data.Length] = LE;
            }
            else if (Data != null && !UseLE)
            {
                pbtAPDU[4] = (byte)Data.Length;
                Data.CopyTo(pbtAPDU, 5);
            }
            else if (Data == null && UseLE)
            {
                pbtAPDU[4] = LE;
            }

            return pbtAPDU;
        }

        public static Apdu Select(ushort id)
        {
            return new Apdu(0x00, 0xA4, 0x00, 0x00, new byte[] { (byte)(id >> 8), (byte)(id & 0xff) }, 0xFF);
        }

        public static Apdu Select(byte[] id)
        {
            return new Apdu(0x00, 0xA4, 0x00, 0x00, id, 0xFF);
        }

        public static Apdu SelectMF()
        {
            return new Apdu(0x00, 0xA4, 0x00, 0x00);
        }

        public static Apdu SelectByAID(byte[] AID)
        {
            return new Apdu(0x00, 0xA4, 0x04, 0x00, AID);
        }

        public static Apdu SelectByAbsolutePath(byte[] path)
        {
            return new Apdu(0x00, 0xA4, 0x08, 0x00, path);
        }

        public static Apdu SelectByRelativePath(byte[] path)
        {
            return new Apdu(0x00, 0xA4, 0x09, 0x00, path);
        }

        public static Apdu Parent()
        {
            return new Apdu(0x00, 0xA4, 0x03, 0x00);
        }

        public static Apdu ReadBinary(int start, byte size)
        {
            return new Apdu(0x00, 0xB0, (byte)(start >> 8), (byte)(start & 0xff), size);
        }

        public static Apdu UpdateBinary(int start, byte[] data)
        {
            return new Apdu(0x00, 0xD6, (byte)(start >> 8), (byte)(start & 0xff), data);
        }

        public static Apdu AppendRecord(byte[] data)
        {
            return new Apdu(0x00, 0xE2, 0x00, 0x00, data);
        }

        public static Apdu ReadRecordCurrent()
        {
            return new Apdu(0x00, 0xB2, 0x00, 0x04, 0x00);
        }

        public static Apdu ReadRecordAbsolute(byte index)
        {
            return new Apdu(0x00, 0xB2, index, 0x04, 0x00);
        }
        public static Apdu ReadRecordFirst()
        {
            return new Apdu(0x00, 0xB2, 0x00, 0x00, 0x00);
        }
        public static Apdu ReadRecordLast()
        {
            return new Apdu(0x00, 0xB2, 0x00, 0x01, 0x00);
        }
        public static Apdu ReadRecordNext()
        {
            return new Apdu(0x00, 0xB2, 0x00, 0x02, 0x00);
        }
        public static Apdu ReadRecordPrevious()
        {
            return new Apdu(0x00, 0xB2, 0x00, 0x03, 0x00);
        }

        public static Apdu UpdateRecordCurrent(byte[] data)
        {
            return new Apdu(0x00, 0xDC, 0x00, 0x04, data);
        }
        public static Apdu UpdateRecordAbsolute(byte index, byte[] data)
        {
            return new Apdu(0x00, 0xDC, index, 0x04, data);
        }
        public static Apdu UpdateRecordFirst(byte[] data)
        {
            return new Apdu(0x00, 0xDC, 0x00, 0x00, data);
        }
        public static Apdu UpdateRecordLast(byte[] data)
        {
            return new Apdu(0x00, 0xDC, 0x00, 0x01, data);
        }
        public static Apdu UpdateRecordNext(byte[] data)
        {
            return new Apdu(0x00, 0xDC, 0x00, 0x02, data);
        }
        public static Apdu UpdateRecordPrev(byte[] data)
        {
            return new Apdu(0x00, 0xDC, 0x00, 0x03, data);
        }
        public static Apdu Verify(bool BackTracking, byte pinID, byte[] pin)
        {
            return new Apdu(0x00, 0x20, 0x00, (byte)(pinID & 0x7F | (BackTracking ? 0x80 : 0)), pin);
        }
        public static Apdu ExternalAuthenticate(bool BackTracking, byte keyID, byte[] data)
        {
            return new Apdu(0x00, 0x82, 0x00, (byte)(keyID & 0x7F | (BackTracking ? 0x80 : 0)), data);
        }
        public static Apdu GetChallenge(byte size)
        {
            return new Apdu(0x00, 0x84, 0x00, 0x00, size);
        }
        public static Apdu GiveRandom(byte[] random)
        {
            return new Apdu(0x80, 0x86, 0x00, 0x00, random);
        }
        public static Apdu InternalAuthenticate(bool BackTracking, byte keyID, byte[] data)
        {
            return new Apdu(0x00, 0x88, 0x00, (byte)(keyID & 0x7F | (BackTracking ? 0x80 : 0)), data, (byte)data.Length);
        }
        public static Apdu ResetRetryCountr(bool BackTracking, byte pinID)
        {
            return Apdu.ResetRetryCounter(BackTracking, pinID, null, null);
        }
        public static Apdu ResetRetryCounter(bool BackTracking, byte pinID, byte[] PUK)
        {
            return Apdu.ResetRetryCounter(BackTracking, pinID, PUK, null);
        }
        public static Apdu ResetRetryCounter(bool BackTracking, byte pinID, byte[] PUK, byte[] newPin)
        {
            byte mode;
            if (PUK == null && newPin == null)
                mode = 3;
            else if (newPin == null)
                mode = 1;
            else
                mode = 0;
            byte[] pPuk = (PUK != null) ? PUK : new byte[0];
            byte[] pPin = (newPin != null) ? newPin : new byte[0];
            byte[] data = new byte[pPuk.Length + pPin.Length];
            pPuk.CopyTo(data, 0);
            pPin.CopyTo(data, pPuk.Length);
            return new Apdu(0x00, 0x2C, mode, (byte)(pinID & 0x7F | (BackTracking ? 0x80 : 0)), data);

        }
        public static Apdu ChangeReferenceData(bool BackTracking, byte pinID, byte[] oldPin, byte[] newPin)
        {
            byte Explicit = 0;
            byte[] data;
            if (oldPin == null)
            {
                data = newPin;
                Explicit = 1;
            }
            else
            {
                data = new byte[oldPin.Length + newPin.Length];
                oldPin.CopyTo(data, 0);
                newPin.CopyTo(data, oldPin.Length);
            }
            return new Apdu(0x00, 0x24, Explicit, (byte)(pinID & 0x7F | (BackTracking ? 0x80 : 0)), data);
        }
        public static Apdu ChangeKeyData(bool BackTracking, byte pinID, byte[] oldPin, byte[] newPin)
        {
            byte Explicit = 0;
            byte[] data;
            if (oldPin == null)
            {
                data = newPin;
                Explicit = 1;
            }
            else
            {
                data = new byte[oldPin.Length + newPin.Length];
                oldPin.CopyTo(data, 0);
                newPin.CopyTo(data, oldPin.Length);
            }
            return new Apdu(0x00, 0x24, Explicit, (byte)(pinID & 0x7F | (BackTracking ? 0x80 : 0)), data);
        }

        public static Apdu GetData(byte mode)
        {
            return new Apdu(0x00, 0xCA, 0x01, mode, 0x00);
        }

        public static byte[] ISOPad(byte[] data)
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
        public static byte[] ANSIPad(byte[] data)
        {
            int padLen;
            if ((data.Length & 0x7) == 0)
                padLen = data.Length;
            else
                padLen = (data.Length - (data.Length & 0x7) + 0x08);
            byte[] padData = new byte[padLen];
            data.CopyTo(padData, 0);
            for (int i = data.Length; i < padData.Length; i++)
                padData[i] = 0;
            return padData;
        }
    }
}
