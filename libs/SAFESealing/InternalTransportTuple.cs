using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
        public Byte[]?               CryptoIV                  { get; set; }
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


        public InternalTransportTuple(CryptoVariant  WithKeyAgreement,
                                      Byte[]?        KeyDiversificationData   = null)
        {

            this.CryptoSettings          = WithKeyAgreement == CryptoVariant.ECDHE_AES

                                               ? new CryptoSettingsStruct(
                                                     AlgorithmSpecCollection.ECDH,
                                                     AlgorithmSpecCollection.ECSECP256R1,
                                                     AlgorithmSpecCollection.SHA256,
                                                     AlgorithmSpecCollection.AES256CBC,
                                                     AlgorithmSpecCollection.COMPRESSION_NONE
                                                 )

                                               : new CryptoSettingsStruct(
                                                     null,
                                                     null,
                                                     null,
                                                     AlgorithmSpecCollection.RSA2048,
                                                     AlgorithmSpecCollection.COMPRESSION_NONE
                                                 );

            this.KeyDiversificationData  = KeyDiversificationData ?? Array.Empty<Byte>();

        }

        #endregion


    }

}
