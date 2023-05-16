
#region Usings

using System.ComponentModel.DataAnnotations;
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


        #region Seal  (Plaintext,   RSAPrivateKey)

        /// <summary>
        /// Perform padding, encryption and formatting for transport of the given plaintext.
        /// </summary>
        /// <param name="Plaintext">A plaintext for sealed transport.</param>
        /// <param name="RSAPrivateKey">A RSA private key.</param>
        public ByteArray Seal(Byte[]         Plaintext,
                              RSAPrivateKey  RSAPrivateKey)
        {

            var rsaWithIntegrityPadding  = RSAPrivateKey.Key.Modulus.BitLength switch {
                                               2048 => new RSAWithIntegrityPadding(AlgorithmSpecCollection.RSA2048),
                                               4096 => new RSAWithIntegrityPadding(AlgorithmSpecCollection.RSA4096),
                                               _    => null
                                           };

            if (rsaWithIntegrityPadding is null)
                return ByteArray.Error("Unsupported RSA key length: " + RSAPrivateKey.Key.Modulus.BitLength);

            // No diversification needed for direct RSA application
            var internalTransportTuple   = new InternalTransportTuple(
                                               new CryptoSettings(
                                                   null,
                                                   null,
                                                   null,
                                                   AlgorithmSpecCollection.RSA2048,
                                                   AlgorithmSpecCollection.COMPRESSION_NONE,
                                                   null,
                                                   (UInt32) RSAPrivateKey.Key.Modulus.BitLength
                                               ),
                                               rsaWithIntegrityPadding.SymmetricIV,  //ToDo(ahzf): This is allways null!?
                                               Array.Empty<Byte>(),
                                               Array.Empty<Byte>()
                                           );

            var payload                  = CompressionMode
                                               ? ByteArray.Ok           (Plaintext)
                                               : SAFESeal. TryToCompress(Plaintext, internalTransportTuple);

            if (payload.HasErrors)
                return payload;

            // Perform asymmetric crypto, symmetric crypto, and padding
            var encryptedData  = rsaWithIntegrityPadding.PadEncryptAndPackage(payload,
                                                                              RSAPrivateKey);

            if (encryptedData.HasErrors)
                return ByteArray.Error("Invalid encrypted data!");

            internalTransportTuple.EncryptedData  = encryptedData;

            // Format the tuple for transport
            return TransportFormatConverter.WrapForTransport(internalTransportTuple);

        }

        #endregion

        #region Reveal(SealedInput, SenderPublicKey)

        /// <summary>
        /// Check the sealing, unseal, verify and return payload data.
        /// </summary>
        /// <param name="SealedInput">A sealed input.</param>
        /// <param name="RSAPublicKey">A RSA public key.</param>
        public ByteArray Reveal(Byte[]        SealedInput,
                                RSAPublicKey  RSAPublicKey)
        {

            var tuple                    = TransportFormatConverter.UnwrapTransportFormat(SealedInput);
            if (tuple.Item1 is null || tuple.Item1.EncryptedData is null || tuple.Item1.EncryptedData.Length == 0)
                return ByteArray.Error("Invalid transport tuple!");

            #region Compression settings

            var compressionOID  = tuple.Item1.CryptoSettings.Compression?.OID;
            if (compressionOID is null)
                return ByteArray.Error("Invalid compression information!");

            if      (compressionOID.Equals(AlgorithmSpecCollection.COMPRESSION_GZIP.OID))
                CompressionMode = true;

            else if (compressionOID.Equals(AlgorithmSpecCollection.COMPRESSION_NONE.OID))
                CompressionMode = false;

            else
                return ByteArray.Error("Invalid or unknown compression!");

            #endregion

            var rsaWithIntegrityPadding  = tuple.Item1.CryptoSettings.EncryptionKeySize switch {
                                               2048 => new RSAWithIntegrityPadding(AlgorithmSpecCollection.RSA2048),
                                               4096 => new RSAWithIntegrityPadding(AlgorithmSpecCollection.RSA4096),
                                               _ => null
                                           };

            if (rsaWithIntegrityPadding is null)
                return ByteArray.Error("The given RSA key size is not supported!");

            var payload                  = rsaWithIntegrityPadding.DecryptAndVerify(tuple.Item1.EncryptedData,
                                                                                    RSAPublicKey);

            return CompressionMode && payload.HasNoErrors
                       ? SAFESeal.InflateZLIBcompressedData(payload)
                       : payload;

        }

        #endregion


    }

}
