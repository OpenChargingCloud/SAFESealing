using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto.Parameters;
using System.Diagnostics;

namespace SAFESealing
{

    /// <summary>
    /// facade for validating (and extracting) sealed OCMF message according to SAFE e.V. specification
    /// </summary>
    public class SAFESealRevealer
    {

        private Boolean keyAgreement;
        private CryptoFactoryImpl cryptoFactory;

        //public Boolean UseECDHE { get; }

        //public SAFESealRevealer(Boolean UseECDHE = false)
        //{
        //    this.UseECDHE = UseECDHE;
        //}



        /**
         * constructor with default algorithm setup.
         *
         * @param useKeyAgreement true if ECDHE key agreement is to be used, false for RSA+IIP
         */
        public SAFESealRevealer(Boolean useKeyAgreement)
        {
            this.keyAgreement   = useKeyAgreement;
            this.cryptoFactory  = new CryptoFactoryImpl();
        }

        /**
         * <p>reveal.</p>
         *
         * @param rawPublicKeySingleSender an array of {@link byte} objects
         * @param rawPrivateKeyRecipient an array of {@link byte} objects
         * @param sealedMessage an array of {@link byte} objects
         * @return an array of {@link byte} objects
         * @throws javax.crypto.BadPaddingException if any.
         */
        public Byte[] Reveal(Byte[] rawPublicKeySingleSender,
                             Byte[] rawPrivateKeyRecipient,
                             Byte[] sealedMessage)
        {
            // todo perform deterministic conversion from bytearrays to keys.
            // then call the "real" function
            throw new Exception();
        }


        /**
         * reveal the validated contents of the sealed message.
         *
         * @param singleSenderPublicKey the public key of the sender
         *                              // additional public keys of different recipients are possible.
         * @param recipientPrivateKey   the private key of the recipient
         * @param sealedMessage         the sealed message
         * @return validated payload data which was sealed
         * @throws javax.crypto.BadPaddingException if processing failed in some way, especially if the seal was not intact anymore.
         *                             This
         */
        public Byte[] Reveal(ECPublicKeyParameters   singleSenderPublicKey,
                             ECPrivateKeyParameters  recipientPrivateKey,
                             Byte[]                  sealedMessage)
        {
            try
            {

                var revealer = new SAFESeal(
                                   cryptoFactory,
                                   keyAgreement
                               );

                return revealer.Reveal(sealedMessage,
                                       recipientPrivateKey,
                                       singleSenderPublicKey);

            }
            catch (Exception e)
            {
                Debug.WriteLine(e); // hiding the specific exception to prevent "padding oracle" type attacks, and simplify usage.
            }

            return Array.Empty<Byte>();

        }

    }

}
