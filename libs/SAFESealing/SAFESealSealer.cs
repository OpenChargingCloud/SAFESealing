
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
        public CryptoVariant  KeyAgreementMode    { get; }

        /// <summary>
        /// Flag shorthand for NONE or ZLIB.
        /// Later versions may use an enum.
        /// </summary>
        public Boolean        CompressionMode     { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new SAFE seal sealer.
        /// </summary>
        /// <param name="KeyAgreementMode">Whether to use ECDHE+AES or RSA cryptography.</param>
        /// <param name="CompressionMode">Flag shorthand for NONE or ZLIB. Later versions may use an enum.</param>
        private SAFESealSealer(CryptoVariant  KeyAgreementMode   = CryptoVariant.ECDHE_AES,
                               Boolean        CompressionMode    = false)
        {

            this.cryptoFactory     = new CryptoFactoryImpl();

            this.KeyAgreementMode  = KeyAgreementMode;
            this.CompressionMode   = CompressionMode;

        }

        #endregion


        #region (static) ECDHE_AES(CompressionMode = false)

        /// <summary>
        /// Create a new SAFE sealer using ECDHE+AES cryptography.
        /// </summary>
        /// <param name="CompressionMode">Flag shorthand for NONE or ZLIB. Later versions may use an enum.</param>
        public static SAFESealSealer ECDHE_AES(Boolean CompressionMode = false)

            => new (CryptoVariant.ECDHE_AES,
                    CompressionMode);

        #endregion

        #region (static) RSA      (CompressionMode = false)

        /// <summary>
        /// Create a new SAFE sealer using RSA cryptography.
        /// </summary>
        /// <param name="CompressionMode">Flag shorthand for NONE or ZLIB. Later versions may use an enum.</param>

        public static SAFESealSealer RSA(Boolean CompressionMode = false)

            => new (CryptoVariant.RSA,
                    CompressionMode);

        #endregion


        #region Seal(SenderPrivateKey,    SingleRecipientPublicKey,    Cl.eartext, Nonce)

        /// <summary>
        /// Seal a cleartext, encrypting and protecting it for transport.
        /// </summary>
        /// <param name="SenderPrivateKey">A private key of the sender.</param>
        /// <param name="SingleRecipientPublicKey">A public key of the single recipient.</param>
        /// <param name="Cleartext">A cleartext to be sealed for transport.</param>
        /// <param name="Nonce">A nonce for increasing the entropy. A random number or a monotonic counter is recommended.</param>
        /// <returns>A sealed message.</returns>
        public Byte[] Seal(ECPrivateKeyParameters  SenderPrivateKey,
                           ECPublicKeyParameters   SingleRecipientPublicKey,
                           Byte[]                  Cleartext,
                           Byte[]                  Nonce)
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
                                Nonce);

            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
            }

            return Array.Empty<Byte>();

        }

        #endregion

        #region Seal(RawPrivateKeySender, RawPublicKeySingleRecipient, Cleartext, Nonce)  // Do not use!

        /// <summary>
        /// Seal a cleartext, encrypting and protecting it for transport.
        /// </summary>
        /// <param name="RawPrivateKeySender">A private key of a sender as an array of bytes.</param>
        /// <param name="RawPublicKeySingleRecipient">A public key of a single recipient as an array of bytes.</param>
        /// <param name="Cleartext">A cleartext to be sealed for transport.</param>
        /// <param name="Nonce">An unique identification assigned to this message. A monotonic counter or similar source is recommended.</param>
        /// <returns>A sealed message.</returns>
        public Byte[] Seal(Byte[] RawPrivateKeySender,
                           Byte[] RawPublicKeySingleRecipient,
                           Byte[] Cleartext,
                           Int64  Nonce)
        {
            return Array.Empty<Byte>();
        }

        #endregion


    }

}
