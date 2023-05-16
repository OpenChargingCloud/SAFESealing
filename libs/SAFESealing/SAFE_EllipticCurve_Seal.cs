
#region Usings

using Org.BouncyCastle.Crypto.Parameters;
using System.Net.WebSockets;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// Sealing and revealing of OCMF messages according to SAFE e.V. specifications
    /// using Elliptic-Curve Cryptography (ECC).
    /// </summary>
    public class SAFE_EllipticCurve_Seal
    {

        #region Properties

        /// <summary>
        /// Flag shorthand for NONE or ZLIB.
        /// Later versions may use an enum.
        /// </summary>
        public Boolean CompressionMode    { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new SAFE seal using Elliptic-Curve Cryptography (ECC).
        /// </summary>
        /// <param name="CompressionMode">Flag shorthand for NONE or ZLIB. Later versions may use an enum.</param>
        public SAFE_EllipticCurve_Seal(Boolean CompressionMode   = false)
        {

            this.CompressionMode  = CompressionMode;

        }

        #endregion


        #region Seal  (Plaintext,   SenderPrivateKey,    RecipientPublicKeys, Nonce)

        /// <summary>
        /// Seal contents: perform calculation of ephemeral key, padding, encryption, and formatting for transport.
        /// </summary>
        /// <param name="Plaintext">A plaintext for sealed transport.</param>
        /// <param name="SenderPrivateKey">A sender private key (caller's key).</param>
        /// <param name="RecipientPublicKeys">An enumeration of recipient public key(s).</param>
        /// <param name="Nonce">A cryptographic nonce for increasing the entropy. A random number or a monotonic counter is recommended.</param>
        /// <returns>The wrapped and sealed message.</returns>
        public ByteArray Seal(Byte[]                              Plaintext,
                              ECPrivateKeyParameters              SenderPrivateKey,
                              IEnumerable<ECPublicKeyParameters>  RecipientPublicKeys,
                              Byte[]                              Nonce)
        {

            var asymmetricLayer  = ECDHEWithIntegrityPadding.AES256ECB;

            var itt              = new InternalTransportTuple(
                                       new CryptoSettings(
                                           AlgorithmSpecCollection.ECDH,
                                           AlgorithmSpecCollection.ECSECP256R1,
                                           AlgorithmSpecCollection.SHA256,
                                           AlgorithmSpecCollection.AES256CBC,
                                           AlgorithmSpecCollection.COMPRESSION_NONE,
                                           null,
                                           AlgorithmSpecCollection.AES256ECB.KeySizeInBit / 8
                                       ),
                                       asymmetricLayer.SymmetricIV,
                                       Array.Empty<Byte>(),
                                       Nonce
                                   );

            var compressed       = CompressionMode
                                       ? ByteArray.Ok           (Plaintext)
                                       : SAFESeal. TryToCompress(Plaintext, itt);

            if (compressed.HasErrors)
                return compressed;

            var encryptedData    = asymmetricLayer.PadEncryptAndPackage(compressed,
                                                                        RecipientPublicKeys,
                                                                        SenderPrivateKey,
                                                                        itt.KeyDiversificationData);

            itt.EncryptedData    = encryptedData;

            return TransportFormatConverter.WrapForTransport(itt);

        }

        #endregion

        #region Reveal(SealedInput, RecipientPrivateKey, SenderPublicKey)

        /// <summary>
        /// Carefully check the sealing, unseal, and return payload data.
        /// Performs transport unwrapping, calculation of ephemeral key, decryption, and integrity validation.
        /// The most important Exception is the BadPaddingException which signals the integrity validation has failed.
        /// </summary>
        /// <param name="SealedInput">An array of bytes.</param>
        /// <param name="RecipientPrivateKey">A private key of a recipient.</param>
        /// <param name="SenderPublicKey">A public key of a sender.</param>
        /// <returns>The plaintext, when everything went OK and the integrity has been validated.</returns>
        public ByteArray Reveal(Byte[]                  SealedInput,
                                       ECPrivateKeyParameters  RecipientPrivateKey,
                                       ECPublicKeyParameters   SenderPublicKey) // is one sender public key enough if several were used in sending?
        {

            var tuple            = TransportFormatConverter.UnwrapTransportFormat(SealedInput);
            if (tuple.Item1 is null || tuple.Item1.EncryptedData is null || tuple.Item1.EncryptedData.Length == 0)
                return ByteArray.Error("Invalid transport tuple!");

            #region Compression settings

            var compressionOID   = tuple.Item1.CryptoSettings.Compression?.OID;
            if (compressionOID is null)
                return ByteArray.Error("Invalid compression information!");

            if      (compressionOID.Equals(AlgorithmSpecCollection.COMPRESSION_GZIP.OID))
                CompressionMode  = true;

            else if (compressionOID.Equals(AlgorithmSpecCollection.COMPRESSION_NONE.OID))
                CompressionMode  = false;

            else
                return ByteArray.Error("Invalid or unknown compression!");

            #endregion


            var payload          = ECDHEWithIntegrityPadding.AES256ECB.

                                       DecryptAndVerify(tuple.Item1.EncryptedData,
                                                        SenderPublicKey,
                                                        RecipientPrivateKey,
                                                        tuple.Item1.KeyDiversificationData,
                                                        tuple.Item1.CryptoIV);

            return CompressionMode && payload.HasNoErrors
                       ? SAFESeal.InflateZLIBcompressedData(payload)
                       : payload;

        }

        #endregion


    }

}
