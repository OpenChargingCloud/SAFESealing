
#region Usings

using System.Text.RegularExpressions;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// Sealing and revealing of OCMF messages according to SAFE e.V. specifications
    /// using RSA cryptography.
    /// </summary>
    public class SAFE_RSA_Seal
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
        /// Create a new SAFE seal using RSA cryptography.
        /// </summary>
        /// <param name="CompressionMode">Flag shorthand for NONE or ZLIB. Later versions may use an enum.</param>
        public SAFE_RSA_Seal(Boolean CompressionMode   = false)
        {

            this.CompressionMode  = CompressionMode;

        }

        #endregion


        #region Seal  (Cleartext,   SenderPrivateKey,    RecipientPublicKeys, Nonce)

        /// <summary>
        /// Seal contents: perform calculation of ephemeral key, padding, encryption, and formatting for transport.
        /// </summary>
        /// <param name="Cleartext">A cleartext for sealed transport.</param>
        /// <param name="SenderRSAPrivateKey">A sender private key (caller's key).</param>
        /// <param name="RecipientPublicKeys">A recipient public key(s).</param>
        /// <param name="Nonce">A cryptographic nonce for increasing the entropy. A random number or a monotonic counter is recommended.</param>
        /// <returns>The wrapped and sealed message.</returns>
        public Byte[] Seal(Byte[]         Cleartext,
                           RSAPrivateKey  SenderRSAPrivateKey)
        {

            // lacking a proper API, we do this the factual way:
            var description               = SenderRSAPrivateKey.ToString();
            var keyLengthFromDescription  = new Regex(@".+RSA private CRT key,\s+(\d{4})\sbits$", RegexOptions.Multiline);
            var match                     = keyLengthFromDescription.Match(description);

            if (match.Success == false)
                throw new Exception("Could not determine RSA key length!");

            var privateKeyLength = UInt32.Parse(match.Groups[1].Value);
            var asymmetricLayer = privateKeyLength switch {
              //1024 => new RSAWithIntegrityPadding(AlgorithmSpecCollection.RSA1024),  //ahzf: RSA1024 is NOT DEFINED within AlgorithmSpecCollection!!?
                2048 => new RSAWithIntegrityPadding(AlgorithmSpecCollection.RSA2048),
                4096 => new RSAWithIntegrityPadding(AlgorithmSpecCollection.RSA4096),
                _    => throw new Exception("Unsupported RSA key length: " + privateKeyLength),
            };

            // No diversification needed for direct RSA application
            var itt            = new InternalTransportTuple(
                                     new CryptoSettings(
                                         null,
                                         null,
                                         null,
                                         AlgorithmSpecCollection.RSA2048,
                                         AlgorithmSpecCollection.COMPRESSION_NONE,
                                         null,
                                         privateKeyLength
                                     ),
                                     asymmetricLayer.SymmetricIV,
                                     Array.Empty<Byte>(),
                                     Array.Empty<Byte>()
                                 );

            var payload        = CompressionMode
                                     ? Cleartext
                                     : SAFESeal.TryToCompress(Cleartext, itt);

            // Perform asymmetric crypto, symmetric crypto, and padding
            itt.EncryptedData  = asymmetricLayer.PadEncryptAndPackage(payload,
                                                                      SenderRSAPrivateKey);

            // Format the tuple for transport
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
        /// <param name="SenderPublicKey">A public key of the sender.</param>
        /// <returns>The cleartext, when everything went OK and the integrity has been validated.</returns>
        public Byte[] Reveal(Byte[]        SealedInput,
                             RSAPublicKey  SenderPublicKey) // is one sender public key enough if several were used in sending?
        {

            var tuple           = TransportFormatConverter.UnwrapTransportFormat(SealedInput)
                                      ?? throw new Exception("Invalid transport tuple!");

            #region Compression settings

            var compressionOID  = (tuple.CryptoSettings.Compression?.OID)
                                      ?? throw new Exception("Invalid compression information!");

            if      (compressionOID.Equals(AlgorithmSpecCollection.COMPRESSION_GZIP.OID))
                CompressionMode = true;

            else if (compressionOID.Equals(AlgorithmSpecCollection.COMPRESSION_NONE.OID))
                CompressionMode = false;

            else
                throw new Exception("Invalid or unknown compression!");

            #endregion

            // @IMPROVEMENT for later versions: allow to for a more flexible selection of algorithms.
            var payload  = (tuple.CryptoSettings.EncryptionKeySize switch {

                                //1024 => new RSAWithIntegrityPadding(AlgorithmSpecCollection.RSA1024),  //ahzf: RSA1024 is NOT DEFINED within AlgorithmSpecCollection!!?
                                2048 => new RSAWithIntegrityPadding(AlgorithmSpecCollection.RSA2048),
                                4096 => new RSAWithIntegrityPadding(AlgorithmSpecCollection.RSA4096),

                                _ => throw new Exception("Specified key size not supported"),

                            }).DecryptAndVerify(tuple.EncryptedData,
                                                SenderPublicKey);

            return CompressionMode
                       ? SAFESeal.InflateZLIBcompressedData(payload)
                       : payload;

        }

        #endregion


    }

}
