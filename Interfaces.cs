using System.IO;
using System;
using System.Collections.Generic;
namespace VirtualSmartCard
{
    public interface ICardHandler
    {
        byte[] ProcessApdu(byte[] apdu);
        byte[] ResetCard(bool warm);
        byte[] ATR { get; }
    }
}