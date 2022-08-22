using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.IO.Pipes;
using System.IO;

namespace VirtualSmartCard.DriverCom
{
    public class PipeCom : IDriverCom
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
                    if (SetCardInserted(value))
                    {
                        cardInserted = value;
                        if (CardInsert != null)
                            CardInsert(value);
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

        NamedPipeClientStream pipe;
        NamedPipeClientStream eventPipe;
        BinaryWriter bwEventPipe;

        Thread driverThread;
        bool running = true;

        public ReaderSettings Settings
        {
            get { return settings; }
        }

        public void Start() {
            if (settings != null)
            {
                driverThread = new Thread(new ThreadStart(Client));
                driverThread.Start();
            }
            else 
                throw new Exception("Connection parameters not set");
        }

        PipeReaderSettings settings = null;
        public PipeCom(PipeReaderSettings settings)
        {
            this.settings = settings;
            handler = new NullHandler();
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
            eventPipe.WaitForPipeDrain();
            return true;
        }
        public void Stop()
        {
            running = false;
            try
            {
                pipe.Flush();
                pipe.WaitForPipeDrain();
                pipe.Close();
            }
            catch { }
            try
            {
                eventPipe.Flush();
                eventPipe.WaitForPipeDrain();
                eventPipe.Close();
            }
            catch { }
            driverThread.Join();
        }

        void Client()
        {
            running = true;
            try
            {
                while (running)
                {
                    pipe = new NamedPipeClientStream(settings.Host, settings.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                    eventPipe = new NamedPipeClientStream(settings.Host, settings.EventPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                    while (running)
                    {
                        try { pipe.Connect(2000); }
                        catch(Exception e)
                        { continue; }
                        break;
                    }

                    Console.WriteLine("[=] Connected to Smartcard Data Pipe");

                    if (!running)
                    {
                        if (pipe.IsConnected)
                            pipe.Close();
                        break;
                    }
                    while (running)
                    {
                        try { eventPipe.Connect(2000); }
                        catch { continue; }
                        break;
                    }
                    if (!running)
                    {
                        if (eventPipe.IsConnected)
                            eventPipe.Close();
                        break;
                    }

                    Console.WriteLine("[=] Connected to Smartcard Event Pipe");
                    BinaryReader brPipe = new BinaryReader(pipe);
                    BinaryWriter bwPipe = new BinaryWriter(pipe);
                    bwEventPipe = new BinaryWriter(eventPipe);
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
                                        //if (command == 0)
                                        //    logMessage("Reset");
                                        //else
                                        //    logMessage("getATR");
                                        break;
                                    case 2:

                                        

                                        int apduLen = brPipe.ReadInt32();
                                        byte[] APDU = new byte[apduLen];
                                        brPipe.Read(APDU, 0, apduLen);

                                        Log($"PDU: {ByteArray.hexDump(APDU)}");

                                        byte[] resp = handler.ProcessApdu(APDU);

                                        Log($"Response: {ByteArray.hexDump(resp)}");

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
                                if (!(e is EndOfStreamException) && !(e is ObjectDisposedException))
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
                    catch (Exception ex)
                    {
                        int p = 0;
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
                        if (pipe.IsConnected)
                            pipe.Close();
                        if (eventPipe.IsConnected)
                            eventPipe.Close();
                        pipe.Dispose();
                        eventPipe.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                Log("Card Exception:" + ex.ToString());
            }
        }
    }
}
