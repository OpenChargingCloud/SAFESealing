#region Usings

using System.Diagnostics;

using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// Sealing of OCMF messages according to SAFE e.V. specifications.
    /// </summary>
    public class SAFESealSealer
    {

        #region Data

        private readonly CryptoFactoryImpl cryptoFactory;

        #endregion

        #region Properties

        /// <summary>
        /// Flag shorthand for NONE (==RSA+IIP) or ECDHE.
        /// Later versions may use an enum.
        /// </summary>
        public Boolean  KeyAgreementMode    { get; }

        /// <summary>
        /// Flag shorthand for NONE or ZLIB.
        /// Later versions may use an enum.
        /// </summary>
        public Boolean  CompressionMode     { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new SAFE seal sealer.
        /// </summary>
        /// <param name="KeyAgreementMode">Flag shorthand for NONE (==RSA+IIP) or ECDHE. Later versions may use an enum.</param>
        /// <param name="CompressionMode">Flag shorthand for NONE or ZLIB. Later versions may use an enum.</param>
        public SAFESealSealer(Boolean  KeyAgreementMode   = false,
                              Boolean  CompressionMode    = false)
        {

            this.cryptoFactory     = new CryptoFactoryImpl();

            this.KeyAgreementMode  = KeyAgreementMode;
            this.CompressionMode   = CompressionMode;

        }

        #endregion


        #region Seal(SenderPrivateKey,    SingleRecipientPublicKey,    Cleartext, UniqueId)

        /// <summary>
        /// Seal a cleartext, encrypting and protecting it for transport.
        /// </summary>
        /// <param name="SenderPrivateKey">A private key of the sender.</param>
        /// <param name="SingleRecipientPublicKey">A public key of the single recipient.</param>
        /// <param name="Cleartext">A cleartext to be sealed for transport.</param>
        /// <param name="UniqueId">An unique identification assigned to this message. A monotonic counter or similar source is recommended.</param>
        /// <returns>A sealed message.</returns>
        public Byte[] Seal(ECPrivateKeyParameters  SenderPrivateKey,
                           ECPublicKeyParameters   SingleRecipientPublicKey,
                           Byte[]                  Cleartext,
                           Int64                   UniqueId)
        {

            try
            {

                return new SAFESeal(
                               cryptoFactory,
                               KeyAgreementMode,
                               CompressionMode
                           ).

                           Seal(Cleartext,
                                SenderPrivateKey,
                                new[] {
                                    SingleRecipientPublicKey
                                },
                                UniqueId);

            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
            }

            return Array.Empty<Byte>();

        }

        #endregion

        #region Seal(RawPrivateKeySender, RawPublicKeySingleRecipient, Cleartext, UniqueId)  // Do not use!

        /// <summary>
        /// Seal for multiple recipients. Not available in version 1.
        /// For use with key agreement protocol.
        /// </summary>
        /// <param name="RawPrivateKeySender">A private key of the sender as an array of bytes.</param>
        /// <param name="RawPublicKeySingleRecipient">A public key of the single recipient as an array of bytes.</param>
        /// <param name="Cleartext">A cleartext to be sealed for transport.</param>
        /// <param name="UniqueId">An unique identification assigned to this message. A monotonic counter or similar source is recommended.</param>
        /// <returns>A sealed message.</returns>
        public Byte[] Seal(Byte[]  RawPrivateKeySender,
                           Byte[]  RawPublicKeySingleRecipient,
                           Byte[]  Cleartext,
                           Int64   UniqueId)
        {
            return Array.Empty<Byte>();
        }

        #endregion


    }

}
