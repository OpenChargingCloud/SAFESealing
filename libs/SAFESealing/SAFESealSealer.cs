
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

        #region Properties

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
        /// <param name="CompressionMode">Flag shorthand for NONE or ZLIB. Later versions may use an enum.</param>
        public SAFESealSealer(Boolean CompressionMode = false)
        {

            this.CompressionMode  = CompressionMode;

        }

        #endregion


        #region Seal(SenderECPrivateKey,  RecipientECPublicKey,        Plaintext, Nonce)

        /// <summary>
        /// Seal a plaintext, encrypting and protecting it for transport.
        /// </summary>
        /// <param name="SenderECPrivateKey">An elliptic curve private key of a sender.</param>
        /// <param name="RecipientECPublicKey">An elliptic curve public key of a recipient.</param>
        /// <param name="Plaintext">A plaintext to be sealed for transport.</param>
        /// <param name="Nonce">A cryptographic nonce for increasing the entropy. A random number or a monotonic counter is recommended.</param>
        public Byte[] Seal(ECPrivateKeyParameters  SenderECPrivateKey,
                           ECPublicKeyParameters   RecipientECPublicKey,
                           Byte[]                  Plaintext,
                           Byte[]                  Nonce)
        {

            try
            {

                return new SAFE_EllipticCurve_Seal(CompressionMode).

                           Seal(Plaintext,
                                SenderECPrivateKey,
                                new[] {
                                    RecipientECPublicKey
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

        #region Seal(SenderRSAPrivateKey,                              Plaintext)

        /// <summary>
        /// Seal a plaintext, encrypting and protecting it for transport.
        /// </summary>
        /// <param name="SenderRSAPrivateKey">A RSA private key of a sender.</param>
        /// <param name="Plaintext">A plaintext to be sealed for transport.</param>
        public Byte[] Seal(RSAPrivateKey  SenderRSAPrivateKey,
                           Byte[]         Plaintext)
        {

            try
            {

                return new SAFE_RSA_Seal(CompressionMode).

                           Seal(Plaintext,
                                SenderRSAPrivateKey);

            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
            }

            return Array.Empty<Byte>();

        }

        #endregion

        #region Seal(RawPrivateKeySender, RawPublicKeySingleRecipient, Plaintext, Nonce)  // Do not use!

        /// <summary>
        /// Seal a plaintext, encrypting and protecting it for transport.
        /// </summary>
        /// <param name="RawPrivateKeySender">A RAW private key of a sender as an array of bytes.</param>
        /// <param name="RawPublicKeySingleRecipient">A RAW public key of a single recipient as an array of bytes.</param>
        /// <param name="Plaintext">A plaintext to be sealed for transport.</param>
        /// <param name="Nonce">An unique identification assigned to this message. A monotonic counter or similar source is recommended.</param>
        public Byte[] Seal(Byte[] RawPrivateKeySender,
                           Byte[] RawPublicKeySingleRecipient,
                           Byte[] Plaintext,
                           Int64  Nonce)
        {
            return Array.Empty<Byte>();
        }

        #endregion


    }

}
