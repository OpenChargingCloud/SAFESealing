
#region Usings

using System.Diagnostics;

using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// Verifying and extracting sealed OCMF message according to SAFE e.V. specifications.
    /// </summary>
    public class SAFESealRevealer
    {

        #region Data

        private readonly CryptoFactoryImpl cryptoFactory;

        #endregion

        #region Properties

        /// <summary>
        /// Flag shorthand for NONE (==RSA+IIP) or ECDHE.
        /// Later versions may use an enum.
        /// </summary>
        public CryptoVariant  KeyAgreementMode    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new SAFE seal revealer.
        /// </summary>
        /// <param name="KeyAgreementMode">Whether to use ECDHE+AES or RSA cryptography.</param>
        public SAFESealRevealer(CryptoVariant KeyAgreementMode = CryptoVariant.ECDHE_AES)
        {

            this.cryptoFactory     = new CryptoFactoryImpl();

            this.KeyAgreementMode  = KeyAgreementMode;

        }

        #endregion


        #region Reveal(SenderPublicKey,    RecipientPrivateKey,    SealedMessage)

        /// <summary>
        /// Verify and reveal a sealed message.
        /// </summary>
        /// <param name="SenderPublicKey">A sender public key.</param>
        /// <param name="RecipientPrivateKey">A private key of a recipient.</param>
        /// <param name="SealedMessage">A sealed message.</param>
        /// <returns>The verified cleartext.</returns>
        public Byte[] Reveal(ECPublicKeyParameters   SenderPublicKey,
                             ECPrivateKeyParameters  RecipientPrivateKey,
                             Byte[]                  SealedMessage)
        {
            try
            {

                return new SAFESeal(
                           cryptoFactory,
                           KeyAgreementMode
                       ).

                       Reveal(SealedMessage,
                              RecipientPrivateKey,
                              SenderPublicKey);

            }
            catch (Exception e)
            {
                // Hiding the specific exception to prevent "padding oracle" type attacks, and simplify usage.
                Debug.WriteLine(e);
            }

            return Array.Empty<Byte>();

        }

        #endregion

        #region Reveal(RawSenderPublicKey, RawRecipientPrivateKey, SealedMessage)

        /// <summary>
        /// Verify and reveal a sealed message.
        /// </summary>
        /// <param name="RawSenderPublicKey">A public key of a sender as an array of bytes.</param>
        /// <param name="RawRecipientPrivateKey">A private key of a recipient as an array of bytes.</param>
        /// <param name="SealedMessage">A sealed message.</param>
        /// <returns>The verified cleartext.</returns>
        public Byte[] Reveal(Byte[] RawSenderPublicKey,
                             Byte[] RawRecipientPrivateKey,
                             Byte[] SealedMessage)
        {
            // todo perform deterministic conversion from bytearrays to keys.
            // then call the "real" function
            return Array.Empty<Byte>();
        }

        #endregion


    }

}
