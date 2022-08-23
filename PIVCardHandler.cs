using System;
using System.Text;
using System.Linq;
using VirtualSmartCard;
using ISO7816;
using System.IO;
using Yubico.Core.Tlv;
using Yubico.YubiKey.Piv.Objects;
using Yubico.Core.Logging;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using System.Collections.Generic;

namespace PIVert {

    public class PIVCardHandler : ICardHandler {

        enum DataObjectType  {
            DiscoveryObject = 0x7e,
            CardCapabilityContainer = 0x5fc107,
            CardHolderUniqieID = 0x5fc102,
            CardHolderFingerPrints = 0x5fc103,
            CardHolderFacialImage = 0x5fc108,            
            CertPIVAuth = 0x5fc105,
            CertCardAuth = 0x5fc101,
            CertSign = 0x5fc10a,
            CertKeyMan = 0x5fc10b,
            SecurityObject = 0x5fc106,
            PrintedInfo = 0x5fc109,
            KeyHistory = 0x005FC10C
        }

        static readonly byte[] PIVAID = new byte[] { 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00 };
        static readonly byte[] DataObjectNotFound = new byte[] { 0x6a, 0x82 };
        static readonly byte[] ErrorUnchanged = new byte[] { 0x61, 00 };
        static readonly byte[] StatusOK = new byte[] { 0x90, 00 };
        static readonly byte[] InstructionNotSupported = new byte[] { 0x6d, 00 };
        static readonly byte[] PIVUsagePolicy = new byte[] { 0x40, 00 };        

        public byte[] ATR => new byte[] { 0x3B, 0x9F, 0x95, 0x81, 0x31, 0xFE, 0x9F, 0x00, 0x66, 0x46, 0x53, 0x05, 0x10, 0x00, 0x11, 0x71, 0xDF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };

        readonly CardCapabilityContainer cardCapabilityContainer = new CardCapabilityContainer();
        readonly CardholderUniqueId cardHolderUID = new CardholderUniqueId();
        readonly Pkcs12Store store = new Pkcs12Store();
        readonly RsaPrivateCrtKeyParameters key;
        readonly byte[] certificateBytes;

        BinaryReader pendingResponse;
        MemoryStream pendingRequest;

        public PIVCardHandler(string pfxPath, string pfxPassword) {
            cardCapabilityContainer.SetRandomCardId();
            cardHolderUID.SetRandomGuid();

            store.Load(new MemoryStream(File.ReadAllBytes(pfxPath)),pfxPassword.ToArray());
            var firstAlias = store.Aliases.Cast<string>().First();
            certificateBytes = store.GetCertificate(firstAlias).Certificate.GetEncoded();
            key = (RsaPrivateCrtKeyParameters)store.GetKey(firstAlias).Key;            
        }

        public int GetInteger(ReadOnlySpan<byte> data) {
            int result = 0;
            for(int idx=0; idx<data.Length; ++idx) {
                result |= data[idx] << ( (data.Length - 1 - idx) * 8);
            }
            return result;
        }

        public byte[] SignData(byte[] dataToSign) {
            RsaEngine engine = new RsaEngine();
            engine.Init(true, key);
            return engine.ProcessBlock(dataToSign, 0, dataToSign.Length);       
        }

        public byte[] GenerateLargeResponse(byte[] data) {

            if (data.Length > 0xff) {

                pendingResponse = new BinaryReader(new MemoryStream(data));
                var response = pendingResponse.ReadBytes(0xff);
                var remaining = Math.Min(0xff, pendingResponse.BaseStream.Length - pendingResponse.BaseStream.Position);
                return response.Concat(new byte[] { 0x61, (byte)remaining }).ToArray();

            } else {
                return data.Concat(StatusOK).ToArray();
            }
        }

        public byte[] ProcessApdu(byte[] apdu) {

            var apduObj = new Apdu(apdu);
            bool chaining = (apduObj.CLA & 0x10) == 0x10;        

            if (apduObj.CLA == 0 || apduObj.CLA == 0x10) {

                if (apduObj.INS == 0xa4 && apduObj.P1 == 0x4) {

                    var aid = apduObj.Data;
                    if (aid.SequenceEqual(PIVAID)) {

                        var tlvResponse = new TlvWriter();

                        using (tlvResponse.WriteNestedTlv(0x61)) {
                            tlvResponse.WriteValue(0x4f, new byte[] { 0x00, 0x00, 0x10, 0x00, 0x01, 0x00 });
                            using (tlvResponse.WriteNestedTlv(0x79)) {
                                tlvResponse.WriteValue(0x4f, PIVAID);
                            }
                            tlvResponse.WriteString(0x50, "PIVert PIV Applet", Encoding.ASCII);
                            using (tlvResponse.WriteNestedTlv(0xac)) {
                                tlvResponse.WriteByte(0x80, 0x3);
                                tlvResponse.WriteByte(0x80, 0x8);
                                tlvResponse.WriteByte(0x80, 0xa);
                                tlvResponse.WriteByte(0x80, 0xc);
                                tlvResponse.WriteByte(0x80, 0x6);
                                tlvResponse.WriteByte(0x80, 0x7);
                                tlvResponse.WriteByte(0x80, 0x11);
                                tlvResponse.WriteByte(0x80, 0x14);
                                tlvResponse.WriteByte(0x6, 0);
                            }
                        }

                        return tlvResponse.Encode().Concat(StatusOK).ToArray();

                    } else {
                        return DataObjectNotFound;
                    }

                } else if (apduObj.INS == 0x20 && apduObj.P1 == 0x00 && apduObj.P2 == 0x80) {

                    Console.WriteLine($"[+] Received verify PIN APDU, allowing any PIN");
                    return StatusOK;

                }else if(apduObj.INS == 0x87) {
                   
                    byte[] data;

                    if (chaining) {
                        if(pendingRequest == null) {
                            pendingRequest = new MemoryStream();
                        }
                        pendingRequest.Write(apduObj.Data, 0, apduObj.Data.Length);
                        return StatusOK;
                    } else {

                        if(pendingRequest != null) {
                            pendingRequest.Write(apduObj.Data, 0, apduObj.Data.Length);
                            data = pendingRequest.ToArray();
                        } else {
                            data = apduObj.Data;
                        }

                        var tlvRequests = new TlvReader(data);
                        var authRequest = tlvRequests.ReadNestedTlv(0x7c);
                        authRequest.ReadValue(0x82);
                        var signData = authRequest.ReadValue(0x81).ToArray();
                        var signature = SignData(signData);
                        var tlvResponse = new TlvWriter();

                        using (tlvResponse.WriteNestedTlv(0x7c)) {
                            tlvResponse.WriteValue(0x82, signature);
                        }

                        Console.WriteLine($"[+] Authenticate APDU recevied, signed message with lengh {signData.Length} bytes");

                        pendingRequest.Close();
                        pendingRequest = null;
                        return GenerateLargeResponse(tlvResponse.Encode());                          
                    }


                }else if(apduObj.INS == 0xc0 && apduObj.P1 == 0 && apduObj.P2 == 0) {

                    if(pendingResponse != null) {

                        var response = pendingResponse.ReadBytes(0xff);
                        var remaining = Math.Min(0xff, pendingResponse.BaseStream.Length - pendingResponse.BaseStream.Position);

                        if(remaining == 0) {
                            pendingResponse.Close();
                            pendingResponse = null;
                            return response.Concat(StatusOK).ToArray();
                        } else {

                            return response.Concat(new byte[] { 0x61, (byte)remaining }).ToArray();
                        }

                    } else {

                        return ErrorUnchanged;
                    }          

                } else if (apduObj.INS == 0xcb && apduObj.P1 == 0x3f && apduObj.P2 == 0xff) {

                    var tlvRequest = new TlvReader(apduObj.Data);
                    var tlvResponse = new TlvWriter();
                    var dataObjectType = (DataObjectType)GetInteger(tlvRequest.ReadValue(0x5c).Span);
                                                                           
                    Console.WriteLine($"[=] Request for PIV DataObject: {dataObjectType}");

                    switch (dataObjectType) {
                        case DataObjectType.DiscoveryObject:

                            using (tlvResponse.WriteNestedTlv(0x7e)) {
                                tlvResponse.WriteValue(0x4f, PIVAID);
                                tlvResponse.WriteValue(0x5f2f, PIVUsagePolicy);
                            };                     

                            return tlvResponse.Encode().Concat(StatusOK).ToArray();

                        case DataObjectType.CardCapabilityContainer:
                                                                                                                                    
                            return cardCapabilityContainer.Encode().Concat(StatusOK).ToArray();

                        case DataObjectType.CardHolderUniqieID:

                            return cardHolderUID.Encode().Concat(StatusOK).ToArray();

                        case DataObjectType.CertPIVAuth:
                        case DataObjectType.CertCardAuth:
                        case DataObjectType.CertSign:

                            using (tlvResponse.WriteNestedTlv(0x53)) {
                                tlvResponse.WriteValue(0x70, certificateBytes);
                                tlvResponse.WriteValue(0x71, new byte[] {00});
                                tlvResponse.WriteValue(0xFE, new byte[] { });
                            };
     
                            return GenerateLargeResponse(tlvResponse.Encode());

                        default:

                            return DataObjectNotFound;                        
                    }                  
                }
            }

            Console.WriteLine($"[=] Unsupported INS {apduObj.INS:x} with CLA {apduObj.CLA:x}");
            return InstructionNotSupported;
        }

        public byte[] ResetCard(bool warm) {
            return ATR;
        }
    }
}
