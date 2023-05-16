
#region Usings

using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// Verify and extract sealed OCMF message according to SAFE e.V. specifications.
    /// </summary>
    public class SAFESealRevealer
    {

        #region Constructor(s)

        /// <summary>
        /// Create a new SAFE seal revealer to verify and extract sealed messages.
        /// </summary>
        public SAFESealRevealer()
        { }

        #endregion


        #region Reveal(SenderPublicKey,    RecipientPrivateKey,    SealedMessage)

        /// <summary>
        /// Verify and reveal a sealed message.
        /// </summary>
        /// <param name="SenderPublicKey">An elliptic curve public key of the sender.</param>
        /// <param name="RecipientPrivateKey">An elliptic curve private key of a recipient.</param>
        /// <param name="SealedMessage">A sealed message.</param>
        public ByteArray Reveal(ECPublicKeyParameters   SenderPublicKey,
                                ECPrivateKeyParameters  RecipientPrivateKey,
                                Byte[]                  SealedMessage)
        {
            try
            {

                return new SAFE_EllipticCurve_Seal().

                           Reveal(SealedMessage,
                                  RecipientPrivateKey,
                                  SenderPublicKey);

            }
            catch (Exception e)
            {
                return ByteArray.Exception(e);
            }

        }

        #endregion

        #region Reveal(SenderPublicKey,    RecipientPrivateKey,    SealedMessage)

        /// <summary>
        /// Verify and reveal a sealed message.
        /// </summary>
        /// <param name="SenderPublicKey">An elliptic curve public key of the sender.</param>
        /// <param name="SealedMessage">A sealed message.</param>
        public ByteArray Reveal(RSAPublicKey  SenderPublicKey,
                                Byte[]        SealedMessage)
        {
            try
            {

                return new SAFE_RSA_Seal().

                           Reveal(SealedMessage,
                                  SenderPublicKey);

            }
            catch (Exception e)
            {
                return ByteArray.Exception(e);
            }

        }

        #endregion

        #region Reveal(RawSenderPublicKey, RawRecipientPrivateKey, SealedMessage)

        /// <summary>
        /// Verify and reveal a sealed message.
        /// </summary>
        /// <param name="RawSenderPublicKey">A RAW public key of a sender as an array of bytes.</param>
        /// <param name="RawRecipientPrivateKey">A RAW private key of a recipient as an array of bytes.</param>
        /// <param name="SealedMessage">A sealed message.</param>
        public ByteArray Reveal(Byte[]  RawSenderPublicKey,
                                Byte[]  RawRecipientPrivateKey,
                                Byte[]  SealedMessage)
        {

            // todo perform deterministic conversion from bytearrays to keys.
            // then call the "real" function
            return ByteArray.Error("Not implemented!");

        }

        #endregion


    }

}
