using Org.BouncyCastle.Crypto.Parameters;
using System.Diagnostics;
using System.Xml;

namespace SAFESealing
{

    /// <summary>
    /// Facade for sealing OCMF messages in encrypted messages, according to SAFE e.V. specifications.
    /// </summary>
    public class SAFESealSealer
    {

        private CryptoFactoryImpl cryptoFactory;

        private Boolean KeyAgreementMode { get; set; }
        //private CryptoFactoryImpl cryptoFactory;
        //private Provider securityProvider;
        private Boolean CompressionMode { get; set; }

        /// <summary>
        /// Default algorithm setup.
        /// </summary>
        /// <param name="Advanced">Set to false for standard RSA+IIP encryption.</param>
        public SAFESealSealer(Boolean Advanced = false)
        {

            this.KeyAgreementMode = Advanced;

            //securityProvider = Security.getProvider("BC");
            //if (securityProvider == null)
            //{
            //    securityProvider = new BouncyCastleProvider();
            //    Security.addProvider(securityProvider);
            //}
            this.cryptoFactory = new CryptoFactoryImpl(); // securityProvider);

        }


        /// <summary>
        /// Seal for multiple recipients. Not available in version 1.
        /// For use with key agreement protocol.
        /// </summary>
        /// <param name="rawPrivateKeySender">an array of {@link byte} objects</param>
        /// <param name="rawPublicKeySingleRecipient">an array of {@link byte} objects</param>
        /// <param name="uniqueID">a {@link java.lang.Long} object</param>
        /// <param name="payloadToSeal">an array of {@link byte} objects</param>
        /// <returns>an array of {@link byte} objects</returns>
        public Byte[] Seal(Byte[]  RawPrivateKeySender,
                           Byte[]  RawPublicKeySingleRecipient,
                           Int64   UniqueID,
                           Byte[]  PayloadToSeal)
        {
            return Array.Empty<Byte>();
        }


        /**
         * seal a payload, encrypting and protecting it for transport.
         *
         * @param senderPrivateKey         private key of the sender
         * @param singleRecipientPublicKey public key of the single recipient
         * @param payloadToSeal            the payload data to be sealed for transport
         * @param uniqueID                 an unique ID assigned to this message. (monotonic counter or similar source recommended.
         * @return sealed message
         * @throws javax.crypto.BadPaddingException     if the sealing failed
         */
        public Byte[] Seal(ECPrivateKeyParameters  SenderPrivateKey,
                           ECPublicKeyParameters   SingleRecipientPublicKey,
                           Byte[]                  PayloadToSeal,
                           Int64                   UniqueID)
        {

            try
            {

                var sealer = new SAFESeal(cryptoFactory) {
                    KeyAgreementMode = KeyAgreementMode,
                    CompressionMode  = CompressionMode
                };

                var publicKeys = new ECPublicKeyParameters[1];
                publicKeys[0]  = SingleRecipientPublicKey;
                var payload    = sealer.Seal(PayloadToSeal, SenderPrivateKey, publicKeys, UniqueID);

                return payload;

            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
            }

            return Array.Empty<Byte>();

        }


    }

}
