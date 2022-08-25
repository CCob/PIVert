# PIVert - PIV smart card emulator

## Introduction

PIVert is a NIST SP 800-73 PIV smart card emulator.  You can supply PIVert with a PFX file containing a certificate and corresponding private key and the tool will emulate the card to Windows as a genuine PIV card.  The card can then be used for authentication over RDP, Citrix and VMWare Horizon using the build in smart card redirection feature.

## Usage

### Installation

On a clean machine that hasn’t used PIVert before, the first step is to install the BixVReader virtual smart card reader driver.  WARNING, this does install a self-signed trusted root certificate authority certificate since the driver is self-signed using a test certificate.  The install step also sets the AllowCertificatesWithNoEKU group policy option.  Without this option, only certificates with the Smartcard Logon EKU are offered for authentication.  With this option enabled, certificates with the User Authentication EKU are also available for authentication.

```
.\PIVert.exe install
[=] AllowCertificatesWithNoEKU on SmartCard Credential Provider not set, enabling...
[+] Enabled AllowCertificatesWithNoEKU on SmartCard Credential Provider
[=] Writing BixVReader.ini config to C:\Windows
[=] Installing driver signing certificate into Root and Trusted Publishers local machine store
[=] Installing driver MSI
[+] Installer completed
```

## Emulating a PIV Card

To emulate a PIV card using a PFX file, you simply specify the PFX file and PFX password as command line arguments. 

```
.\PIVert.exe .\Administrator.pfx password
[=] Connected to Smartcard Data Pipe
[=] Connected to Smartcard Event Pipe
[+] Connected Virtal Smart Card Driver
[+] Virtual card inserted
[=] Press ESC to exit, or any other key to remove and reinsert the virtual card?
[=] Unsupported INS ca with CLA 0
[=] Request for PIV DataObject: CardHolderUniqieID
[=] Request for PIV DataObject: CertPIVAuth
[=] Request for PIV DataObject: CertSign
[=] Request for PIV DataObject: CertKeyMan
[=] Request for PIV DataObject: CertCardAuth
[=] Request for PIV DataObject: KeyHistory
[=] Request for PIV DataObject: CertPIVAuth
[=] Request for PIV DataObject: CertSign
[=] Request for PIV DataObject: CertCardAuth
[=] Request for PIV DataObject: CardHolderUniqieID
[=] Request for PIV DataObject: CertKeyMan
[=] Request for PIV DataObject: KeyHistory
```

There does appear to be a bug in the driver (or potentially my code :D) were sometimes the virtual card insertion is not detected by Windows due issues reading the ATR from the virtual card.  To combat this issue you can press any key other than ESC to virtually remove and re-insert the card.  You’ll know when this as happened as you won’t see the requests for DataObjects on start-up like above.

## Acknowledgements

* Fabio Ottavi for BixVReader UDMF driver ([https://www.codeproject.com/Articles/134010/An-UMDF-Driver-for-a-Virtual-Smart-Card-Reader])
* Frank Morgner and the Virtual Smart Card Project ([https://github.com/frankmorgner/vsmartcard/tree/master/virtualsmartcard])
* Yibico and the Yubikey .NET SDK which some code has made it's way into PIVert ([https://github.com/Yubico/Yubico.NET.SDK])
