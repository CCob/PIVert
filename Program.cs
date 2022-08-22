using Microsoft.Win32;
using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using VirtualSmartCard;
using VirtualSmartCard.DriverCom;

namespace PIVert {
    class Program {

        static PipeCom pipeCom;
        static ManualResetEvent driverConnected = new ManualResetEvent(false);
        static bool verbose = false;
        static string readerConfig = @"[Driver]
NumReaders=1

[Reader0]
        RPC_TYPE=0
VENDOR_NAME=Virtual Smart Card
VENDOR_IFD_TYPE = Pipe Reader
DECIVE_UNIT = 0
";

        public enum INSTALLMESSAGE {
            INSTALLMESSAGE_FATALEXIT = 0x00000000, // premature termination, possibly fatal OOM
            INSTALLMESSAGE_ERROR = 0x01000000, // formatted error message
            INSTALLMESSAGE_WARNING = 0x02000000, // formatted warning message
            INSTALLMESSAGE_USER = 0x03000000, // user request message
            INSTALLMESSAGE_INFO = 0x04000000, // informative message for log
            INSTALLMESSAGE_FILESINUSE = 0x05000000, // list of files in use that need to be replaced
            INSTALLMESSAGE_RESOLVESOURCE = 0x06000000, // request to determine a valid source location
            INSTALLMESSAGE_OUTOFDISKSPACE = 0x07000000, // insufficient disk space message
            INSTALLMESSAGE_ACTIONSTART = 0x08000000, // start of action: action name & description
            INSTALLMESSAGE_ACTIONDATA = 0x09000000, // formatted data associated with individual action item
            INSTALLMESSAGE_PROGRESS = 0x0A000000, // progress gauge info: units so far, total
            INSTALLMESSAGE_COMMONDATA = 0x0B000000, // product info for dialog: language Id, dialog caption
            INSTALLMESSAGE_INITIALIZE = 0x0C000000, // sent prior to UI initialization, no string data
            INSTALLMESSAGE_TERMINATE = 0x0D000000, // sent after UI termination, no string data
            INSTALLMESSAGE_SHOWDIALOG = 0x0E000000 // sent prior to display or authored dialog or wizard
        }

        public enum INSTALLLOGMODE  // bit flags for use with MsiEnableLog and MsiSetExternalUI
        {
            INSTALLLOGMODE_FATALEXIT = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_FATALEXIT >> 24)),
            INSTALLLOGMODE_ERROR = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_ERROR >> 24)),
            INSTALLLOGMODE_WARNING = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_WARNING >> 24)),
            INSTALLLOGMODE_USER = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_USER >> 24)),
            INSTALLLOGMODE_INFO = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_INFO >> 24)),
            INSTALLLOGMODE_RESOLVESOURCE = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_RESOLVESOURCE >> 24)),
            INSTALLLOGMODE_OUTOFDISKSPACE = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_OUTOFDISKSPACE >> 24)),
            INSTALLLOGMODE_ACTIONSTART = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_ACTIONSTART >> 24)),
            INSTALLLOGMODE_ACTIONDATA = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_ACTIONDATA >> 24)),
            INSTALLLOGMODE_COMMONDATA = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_COMMONDATA >> 24)),
            INSTALLLOGMODE_PROPERTYDUMP = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_PROGRESS >> 24)), // log only
            INSTALLLOGMODE_VERBOSE = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_INITIALIZE >> 24)), // log only
            INSTALLLOGMODE_EXTRADEBUG = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_TERMINATE >> 24)), // log only
            INSTALLLOGMODE_LOGONLYONERROR = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_SHOWDIALOG >> 24)), // log only    
            INSTALLLOGMODE_PROGRESS = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_PROGRESS >> 24)), // external handler only
            INSTALLLOGMODE_INITIALIZE = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_INITIALIZE >> 24)), // external handler only
            INSTALLLOGMODE_TERMINATE = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_TERMINATE >> 24)), // external handler only
            INSTALLLOGMODE_SHOWDIALOG = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_SHOWDIALOG >> 24)), // external handler only
            INSTALLLOGMODE_FILESINUSE = (1 << (INSTALLMESSAGE.INSTALLMESSAGE_FILESINUSE >> 24)), // external handler only
        }

        public enum INSTALLLOGATTRIBUTES // flag attributes for MsiEnableLog
        {
            INSTALLLOGATTRIBUTES_APPEND = (1 << 0),
            INSTALLLOGATTRIBUTES_FLUSHEACHLINE = (1 << 1),
        }


        [DllImport("msi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern uint MsiInstallProduct(string packagePath, string commandLine);

        [DllImport("msi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern uint MsiEnableLog(INSTALLLOGMODE dwLogMode, string szLogFile, INSTALLLOGATTRIBUTES dwLogAttributes);



        static void InstallCert(StoreName storeName, string file) {
            var cert = new X509Certificate2(File.ReadAllBytes(file));
            var store = new X509Store(storeName, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
            store.Close();

            store = new X509Store(storeName, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
            store.Close();
        }



        static void PrintUsage() {
            Console.WriteLine("Usage: PIVert.exe install | pfx_file pfx_password");
            return;
        }

        static void InstallDriver() {

            try {
                var driverFolder = Path.Combine(Path.GetDirectoryName(Path.Combine(Assembly.GetEntryAssembly().Location)), "Driver");

                Console.WriteLine("[=] Writing BixVReader.ini config to C:\\Windows");
                File.WriteAllText(@"C:\Windows\BixVReader.ini", readerConfig);
                Console.WriteLine("[=] Installing driver signing certificate into Root and Trusted Publishers local machine store");
                InstallCert(StoreName.Root, Path.Combine(driverFolder, "BixVReader-Cert.cer"));
                InstallCert(StoreName.TrustedPublisher, Path.Combine(driverFolder, "BixVReader-Cert.cer"));
                Console.WriteLine("[=] Installing driver MSI");

                MsiEnableLog(INSTALLLOGMODE.INSTALLLOGMODE_INFO, Path.Combine(driverFolder, "install.log"), 0);
                uint result = MsiInstallProduct(Path.Combine(driverFolder, "BixVReaderInstaller.msi"), "");

                if (result == 0) {
                    Console.WriteLine("[+] Installer completed");
                } else {
                    Console.WriteLine($"[!] Failed to install MSI with error {result}");
                }

            }catch(Exception e) {
                Console.WriteLine($"[!] Failed to install the virtual smart card reader device: {e.Message}");
            }
        }

        static void RunEmulation(string pfxFile, string pfxPassword) {

            try {
                var allowAnyEKU = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider", "AllowCertificatesWithNoEKU", 0);

                if (allowAnyEKU == null || ((int)allowAnyEKU) == 0) {
                    Console.WriteLine("[=] AllowCertificatesWithNoEKU on SmartCard Credential Provider not set, enabling...");
                    Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider", "AllowCertificatesWithNoEKU", 1);
                    Console.WriteLine("[+] Enabled AllowCertificatesWithNoEKU on SmartCard Credential Provider");
                }
            } catch (UnauthorizedAccessException) {
                Console.WriteLine("[!] Failed to set AllowCertificatesWithNoEKU on SmartCard Credential Provider, are you admin?  Only certificates with SmartCard Logon EKU will work.");
            }

            var cardSettings = (PipeReaderSettings)ReaderSettings.LocalPipe();

            pipeCom = new PipeCom(cardSettings);
            pipeCom.Handler = new PIVCardHandler(pfxFile, pfxPassword);
            pipeCom.DriverConnect += PipeCom_DriverConnect;
            pipeCom.CardInsert += PipeCom_CardInsert;
            pipeCom.log += PipeCom_log;
            pipeCom.Start();
            if (driverConnected.WaitOne(10000)) {

                Thread.Sleep(1000);
                pipeCom.CardInserted = true;

                Console.WriteLine("[=] Press ESC to exit, or any other key to remove and reinsert the virtual card?");

                while (Console.ReadKey(true).Key != ConsoleKey.Escape) {
                    pipeCom.CardInserted = false;
                    Thread.Sleep(1000);
                    pipeCom.CardInserted = true;
                }

                pipeCom.CardInserted = false;
                pipeCom.DriverConnected = false;
                pipeCom.Stop();

            } else {
                Console.WriteLine("[!] Failed to connect to Virtual Smart Card, is the driver installed?");
            }

        }


        static void Main(string[] args) {

            if(args.Length == 1 && args[0] != "install" && args.Length != 2) {
                PrintUsage();
                return;
            }

            if(args.Length == 1) {
                InstallDriver();
            } else {
                RunEmulation(args[0], args[1]);
            }                                           
        }

        private static void PipeCom_CardInsert(bool inserted) {
            Console.WriteLine($"[+] Virtual card {(inserted ? "inserted" : "removed")}");
        }

        private static void PipeCom_log(object obj) {
            if(verbose)
                Console.WriteLine(obj);
        }

        private static void PipeCom_DriverConnect(bool connected) {
            driverConnected.Set();
            Console.WriteLine($"[+] {(connected ? "Connected" : "Disconnected")} Virtal Smart Card Driver");
        }
    }
}
