

namespace SAFESealing
{

    /// <summary>
    /// Package-private class to combine the data from and to transport format.
    /// Used to simplify parameter passing between TransportFormatConverter and asymmetric crypto.
    /// </summary>
    public class InternalTransportTuple
    {

        #region Properties

        public CryptoSettingsStruct  CryptoSettings            { get; }
        public Byte[]                CryptoIV                  { get; }
        public Byte[]?               EncryptedData             { get; set; }
        public Byte[]                KeyDiversificationData    { get; }

        #endregion

        #region Constructor(s)

        public InternalTransportTuple(CryptoSettingsStruct  CryptoSettings,
                                      Byte[]                CryptoIV,
                                      Byte[]                EncryptedData,
                                      Byte[]                KeyDiversificationData)
        {

            this.CryptoSettings          = CryptoSettings;
            this.CryptoIV                = CryptoIV;
            this.EncryptedData           = EncryptedData;
            this.KeyDiversificationData  = KeyDiversificationData;

        }

        #endregion


    }

}
