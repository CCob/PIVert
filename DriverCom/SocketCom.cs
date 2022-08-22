using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Net.Sockets;
using System.IO;

namespace VirtualSmartCard.DriverCom
{
    public class SocketCom : IDriverCom
    {
        public ICardHandler handler;
        public ICardHandler Handler { set { handler = value; } }

        public event Action<Object> log;
        public event Action<bool> DriverConnect;
        public event Action<bool> CardInsert;

        bool cardInserted = false;
        public bool CardInserted
        {
            get { return cardInserted; }
            set
            {
                if (cardInserted != value && DriverConnected)
                {
                    if (value && handler.ATR == null)
                    {
                        cardInserted = false;
                        return;
                    }
                    try
                    {
                        if (SetCardInserted(value))
                        {
                            cardInserted = value;
                            if (CardInsert != null)
                                CardInsert(value);
                        }
                    }
                    catch (Exception ex) {
                        Log(ex.ToString());
                    }
                }
            }
        }

        bool driverConnected = false;
        public bool DriverConnected
        {
            get { return driverConnected; }
            set
            {
                if (driverConnected != value)
                {
                    driverConnected = value;
                    //cardInserted = false;
                    if (DriverConnect != null)
                        DriverConnect(value);
                }
            }
        }
        public void Log(object logMsg)
        {
            if (log != null)
                log(logMsg);
        }

        public void Log(byte[] logMsg)
        {
            if (log != null)
                log(ByteArray.hexDump(logMsg));
        }

        Socket socket;
        Socket eventSocket;
        BinaryWriter bwEventPipe;

        Thread driverThread;
        bool running = true;
        string readerName;

        public ReaderSettings Settings
        {
            get { return settings; }
        }

        public void Start()
        {
            if (settings != null)
            {
                driverThread = new Thread(new ThreadStart(Client));
                driverThread.Start();
            }
            else
                throw new Exception("Connection parameters not set");
        }

        TcpIpReaderSettings settings = null;
        public SocketCom(TcpIpReaderSettings settings)
        {
            handler = new NullHandler();
            this.settings = settings;
        }
        
        bool SetCardInserted(bool inserted)
        {
            Int32 command;
            if (inserted)
            {
                Log("Card Inserted");
                command = 1;
            }
            else
            {
                Log("Card Removed");
                command = 0;
            }
            bwEventPipe.Write(command);
            bwEventPipe.Flush();
            return true;
        }

        public void Stop()
        {
            running = false;
            try
            {
                socket.Disconnect(false);
                socket.Close();
            }
            catch { }
            try
            {
                eventSocket.Disconnect(false);
                eventSocket.Close();
            }
            catch { }
            driverThread.Join();
        }
        void Client()
        {
            running = true;
            while (running)
            {
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                eventSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                while (running)
                {
                    try { socket.Connect(settings.Host, settings.Port); }
                    catch { continue; }
                    break;
                }
                if (!running)
                {
                    if (socket.Connected)
                        socket.Close();
                    break;
                }
                while (running)
                {
                    try { eventSocket.Connect(settings.Host, settings.EventPort); }
                    catch { continue; }
                    break;
                }
                if (!running)
                {
                    if (eventSocket.Connected)
                        eventSocket.Close();
                    break;
                }
                var socketStream = new NetworkStream(socket);
                var eventSocketStream = new NetworkStream(eventSocket);
                BinaryReader brPipe = new BinaryReader(socketStream);
                BinaryWriter bwPipe = new BinaryWriter(socketStream);
                bwEventPipe = new BinaryWriter(eventSocketStream);
                DriverConnected = true;
                try
                {
                    while (running)
                    {
                        try
                        {
                            int command = brPipe.ReadInt32();
                            switch (command)
                            {
                                case 0:
                                    handler.ResetCard(true);
                                    Log("Reset");
                                    if (cardInserted)
                                    {
                                        var ATR = handler.ATR;
                                        bwPipe.Write((Int32)ATR.Length);
                                        bwPipe.Write(ATR, 0, ATR.Length);
                                        bwPipe.Flush();
                                    }
                                    else
                                    {
                                        bwPipe.Write((Int32)0);
                                        bwPipe.Flush();
                                    }
                                    break;
                                case 1:
                                    if (cardInserted)
                                    {
                                        var ATR = handler.ATR;
                                        bwPipe.Write((Int32)ATR.Length);
                                        bwPipe.Write(ATR, 0, ATR.Length);
                                        bwPipe.Flush();
                                    }
                                    else
                                    {
                                        bwPipe.Write((Int32)0);
                                        bwPipe.Flush();
                                    }
                                    break;
                                case 2:

                                    int apduLen = brPipe.ReadInt32();
                                    byte[] APDU = new byte[apduLen];
                                    brPipe.Read(APDU, 0, apduLen);
                                    byte[] resp = handler.ProcessApdu(APDU);

                                    if (resp != null)
                                    {
                                        bwPipe.Write((Int32)resp.Length);
                                        bwPipe.Write(resp, 0, resp.Length);
                                    }
                                    else
                                        bwPipe.Write((Int32)0);
                                    bwPipe.Flush();
                                    break;
                            }
                        }
                        catch (Exception e)
                        {
                            if (!(e is EndOfStreamException) && !(e is ObjectDisposedException) && !(e is IOException))
                                Log(e.ToString());
                            if (running)
                            {
                                break;
                            }
                            else
                            {
                                Log("Card Stop");
                                return;
                            }
                        }
                    }
                }
                finally
                {
                    if (cardInserted)
                    {
                        cardInserted = false;
                        if (CardInsert != null)
                            CardInsert(false);
                    }
                    DriverConnected = false;
                    if (socket.Connected)
                        socket.Close();
                    if (eventSocket.Connected)
                        eventSocket.Close();
                }
            }
        }
    }
}
