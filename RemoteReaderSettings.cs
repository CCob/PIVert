namespace VirtualSmartCard {
    public abstract class ReaderSettings
    {
        public string Name { get; set; }
        public string Host { get; set; }
        public bool IsRemote { get; set; }

        static public ReaderSettings LocalPipe() {
            var result = new PipeReaderSettings();
            result.Host = ".";
            result.IsRemote = false;
            result.Name = "LocalReader";
            result.PipeName = "SCardSimulatorDriver0";
            result.EventPipeName  = "SCardSimulatorDriverEvents0";
            return result;
        }


        public override string ToString()
        {
            if (IsRemote)
                return Host + "\\" + Name;
            else
                return Name;
        }
    }

    public class TcpIpReaderSettings : ReaderSettings
    {
        internal TcpIpReaderSettings() { }
        public int Port {get;set;}
        public int EventPort {get;set;}
    }

    public class PipeReaderSettings : ReaderSettings
    {
        internal PipeReaderSettings() { }
        public string PipeName { get; set; }
        public string EventPipeName { get; set; }
    }
}
