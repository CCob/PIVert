namespace VirtualSmartCard {
    public interface ICardHandler
    {
        byte[] ProcessApdu(byte[] apdu);
        byte[] ResetCard(bool warm);
        byte[] ATR { get; }
    }
}