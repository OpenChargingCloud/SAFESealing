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

        public CryptoSettingsStruct  CryptoSettings            { get; set; }

        public Byte[]?               CryptoIV                  { get; set; }
        public Byte[]?               EncryptedData             { get; set; }

        public Byte[]?               KeyDiversificationData    { get; set; }

        public void SetDiversification(Int64 NumericalValue)
        {
            KeyDiversificationData = BitConverter.GetBytes(NumericalValue);
        }



        /// <summary>
        /// Create a new InternalTransportTuple.
        /// </summary>
        /// <param name="css">css a {@link com.metabit.custom.safe.safeseal.impl.CryptoSettingsStruct} object</param>
        public InternalTransportTuple(CryptoSettingsStruct CryptoSettings)
        {
            this.CryptoSettings = CryptoSettings;
        }


        public InternalTransportTuple(Boolean WithKeyAgreement)
        {

            this.CryptoSettings = WithKeyAgreement

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

            //@TODO still, add the magic

        }


    }

}
