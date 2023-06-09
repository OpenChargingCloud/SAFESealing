﻿

namespace SAFESealing
{

    /// <summary>
    /// Package-private class to combine the data from and to transport format.
    /// Used to simplify parameter passing between TransportFormatConverter and asymmetric crypto.
    /// </summary>
    public class InternalTransportTuple
    {

        #region Properties

        public CryptoSettings  CryptoSettings            { get; }
        public Byte[]          CryptoIV                  { get; }
        public Byte[]?         EncryptedData             { get; set; }  //ToDo(ahzf): Solve knotting and make this readonly!
        public Byte[]          KeyDiversificationData    { get; }

        #endregion

        #region Constructor(s)

        public InternalTransportTuple(CryptoSettings  CryptoSettings,
                                      Byte[]          CryptoIV,
                                      Byte[]          EncryptedData,
                                      Byte[]          KeyDiversificationData)
        {

            this.CryptoSettings          = CryptoSettings;
            this.CryptoIV                = CryptoIV;
            this.EncryptedData           = EncryptedData;
            this.KeyDiversificationData  = KeyDiversificationData;

        }

        #endregion

    }

}
