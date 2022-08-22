using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace VirtualSmartCard.DriverCom
{
    public interface IDriverCom
    {
        event Action<Object> log;
        void Log(object logMsg);
        void Log(byte[] logMsg);

        ReaderSettings Settings { get; }
        void Start();
        void Stop();

        bool CardInserted { get; set; }
        event Action<bool> CardInsert;

        bool DriverConnected { get; set; }
        event Action<bool> DriverConnect;

        ICardHandler Handler { set; }
    }

    class NullHandler : ICardHandler
    {
        public byte[] ProcessApdu(byte[] apdu)
        {
            return null;
        }

        public byte[] ResetCard(bool warm)
        {
            return null;
        }

        public byte[] ATR
        {
            get { return null; }
        }

        public bool IsCardInserted
        {
            get { return false; }
        }
    }
}
