
#region Usings

using System.IO.Compression;
using System.Text.RegularExpressions;

using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing
{

    public enum CryptoVariant
    {
        ECDHE_AES,
        RSA
    }


    /// <summary>
    /// Sealing and revealing of OCMF messages according to SAFE e.V. specifications.
    /// </summary>
    public class SAFESeal
    {

        #region Data

        private readonly ICryptoFactory                 cryptoFactory;
        private readonly TransportFormatConverter       formatConverter;
        private          IAsymmetricEncryptionWithIIP?  asymmetricLayer;

        #endregion

        #region Properties

        /// <summary>
        /// Whether to use ECDHE+AES or RSA cryptography.
        /// </summary>
        public CryptoVariant  KeyAgreementMode    { get;}

        /// <summary>
        /// Flag shorthand for NONE or ZLIB.
        /// Later versions may use an enum.
        /// </summary>
        public  Boolean       CompressionMode     { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new SAFE seal.
        /// </summary>
        /// <param name="CryptoFactory">A crypto factory.</param>
        /// <param name="KeyAgreementMode">Whether to use ECDHE+AES or RSA cryptography.</param>
        /// <param name="CompressionMode">Flag shorthand for NONE or ZLIB. Later versions may use an enum.</param>
        public SAFESeal(ICryptoFactory  CryptoFactory,
                        CryptoVariant   KeyAgreementMode,
                        Boolean         CompressionMode   = false)
        {

            this.cryptoFactory     = CryptoFactory;
            this.formatConverter   = new TransportFormatConverter();
            this.KeyAgreementMode  = KeyAgreementMode;
            this.CompressionMode   = CompressionMode;

        }

        #endregion


        #region Seal  (Cleartext,   SenderPrivateKey,    RecipientPublicKeys, Nonce)

        /// <summary>
        /// Seal contents: perform calculation of ephemeral key, padding, encryption, and formatting for transport.
        /// </summary>
        /// <param name="Cleartext">A cleartext for sealed transport.</param>
        /// <param name="SenderPrivateKey">A sender private key (caller's key).</param>
        /// <param name="RecipientPublicKeys">A recipient public key(s).</param>
        /// <param name="Nonce">A nonce for increasing the entropy. A random number or a monotonic counter is recommended.</param>
        /// <returns>The wrapped and sealed message.</returns>
        public Byte[] Seal(Byte[]                              Cleartext,
                           ECPrivateKeyParameters              SenderPrivateKey,
                           IEnumerable<ECPublicKeyParameters>  RecipientPublicKeys,
                           Byte[]                              Nonce)
        {

            var itt = new InternalTransportTuple(KeyAgreementMode, Nonce);

            if (KeyAgreementMode == CryptoVariant.ECDHE_AES)
            {
                // ECDHE + AES
                asymmetricLayer = new ECDHEWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.AES256ECB);
            }
            else
            {
                // RSA

                // lacking a proper API, we do this the factual way:
                var description               = SenderPrivateKey.ToString();
                var keyLengthFromDescription  = new Regex(@".+RSA private CRT key,\s+(\d{4})\sbits$", RegexOptions.Multiline);
                var match                     = keyLengthFromDescription.Match(description);

                if (match.Success == false)
                    throw new Exception("Could not determine RSA key length!");

                var privateKeyLength = UInt32.Parse(match.Groups[1].Value);
                asymmetricLayer = privateKeyLength switch {
                  //1024 => new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA1024),  //ahzf: RSA1024 is NOT DEFINED within AlgorithmSpecCollection!!?
                    2048 => new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA2048),
                    4096 => new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA4096),
                    _    => throw new Exception("Unsupported RSA key length: " + privateKeyLength),
                };

                itt.CryptoSettings.EncryptionKeySize = privateKeyLength;
                // no diversification needed for direct RSA application

            }

            var payload        = CompressionMode
                                     ? Cleartext
                                     : TryToCompress(Cleartext, itt);

            // Perform asymmetric crypto, symmetric crypto, and padding
            itt.EncryptedData  = asymmetricLayer.PadEncryptAndPackage(payload,
                                                                      RecipientPublicKeys,
                                                                      SenderPrivateKey,
                                                                      itt.KeyDiversificationData);

            itt.CryptoIV       = asymmetricLayer.SymmetricIV;

            // Format the tuple for transport
            return formatConverter.WrapForTransport(itt);

        }

        #endregion

        #region Reveal(SealedInput, RecipientPrivateKey, SenderPublicKey)

        /// <summary>
        /// Carefully check the sealing, unseal, and return payload data.
        /// Performs transport unwrapping, calculation of ephemeral key, decryption, and integrity validation.
        /// The most important Exception is the BadPaddingException which signals the integrity validation has failed.
        /// </summary>
        /// <param name="SealedInput">An array of bytes.</param>
        /// <param name="RecipientPrivateKey">A private key of the recipient.</param>
        /// <param name="SenderPublicKey">A public key of the sender.</param>
        /// <returns>The cleartext, when everything went OK and the integrity has been validated.</returns>
        public Byte[] Reveal(Byte[]                  SealedInput,
                             ECPrivateKeyParameters  RecipientPrivateKey,
                             ECPublicKeyParameters   SenderPublicKey) // is one sender public key enough if several were used in sending?
        {

            var tuple           = formatConverter.UnwrapTransportFormat(SealedInput);

            #region Compression settings

            var compressionOID  = (tuple.CryptoSettings.Compression?.OID) ?? throw new Exception("Invalid compression information!");

            if      (compressionOID.Equals(AlgorithmSpecCollection.COMPRESSION_GZIP.OID))
                CompressionMode = true;

            else if (compressionOID.Equals(AlgorithmSpecCollection.COMPRESSION_NONE.OID))
                CompressionMode = false;

            else
                throw new Exception("Invalid or unknown compression!");

            #endregion


            // @IMPROVEMENT for later versions: allow to for a more flexible selection of algorithms.
            asymmetricLayer     = KeyAgreementMode == CryptoVariant.ECDHE_AES

                                      ? new ECDHEWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.AES256ECB)

                                      : tuple.CryptoSettings.EncryptionKeySize switch {

                                          //1024 => new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA1024),  //ahzf: RSA1024 is NOT DEFINED within AlgorithmSpecCollection!!?
                                            2048 => new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA2048),
                                            4096 => new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA4096),

                                            _    => throw new Exception("Specified key size not supported"),

                                        };

            var payload         = asymmetricLayer.DecryptAndVerify(tuple.EncryptedData,
                                                                   SenderPublicKey,
                                                                   RecipientPrivateKey,
                                                                   tuple.KeyDiversificationData,
                                                                   tuple.CryptoIV);

            return CompressionMode
                       ? InflateZLIBcompressedData(payload)
                       : payload;

        }

        #endregion


        #region InflateZLIBcompressedData(CompressedData)

        /// <summary>
        /// Try to decompress if we've got compressed data.
        /// Using "nowrap" settings, we have neither header nor checksum.
        /// </summary>
        /// <param name="Payload">Data to decompress/inflate</param>
        /// <returns>Decompressed/inflated data</returns>
        private Byte[] InflateZLIBcompressedData(Byte[] CompressedData)
        {

            Byte[] decompressedData;

            using (var compressedStream = new MemoryStream(CompressedData))
            {
                using (var deflateStream = new DeflateStream(compressedStream, System.IO.Compression.CompressionMode.Decompress))
                {
                    using (var decompressedStream = new MemoryStream())
                    {
                        deflateStream.CopyTo(decompressedStream);
                        decompressedData = decompressedStream.ToArray();
                    }
                }
            }

            return decompressedData;


            //var inflater   = new Inflater(true); // nowrap is important for our use case.

            //var inputSize  = Payload.Length;
            //// measuring the required input size
            //int outputSize;
            //int tmpSize    = 0;
            //do
            //{
            //    tmpSize += inputSize; // try multiple times with increasing buffer size
            //    inflater.setInput(Payload);

            //    var tmp = new Byte[tmpSize]; // heuristics here.
            //    outputSize = inflater.inflate(tmp);
            //    if (outputSize == 0)
            //        throw new Exception("Input compression level not handled");
            //    inflater.reset();
            //}
            //while (tmpSize == outputSize); // if the temp buffer was completely full, we need to try again with a larger buffer.

            //// now performing actual decompression
            //var result = new byte[outputSize];
            //inflater.setInput(Payload);
            //inflater.inflate(result);
            //inflater.end();

            //return result;

        }

        #endregion

        #region TryToCompress(RAWPayload, ITT)

        /// <summary>
        /// Try to apply ZLIB compression.
        /// Important: Zlib wrapper fields must not be used/sent.
        /// That also implies we always use the same settings in this context: BEST_COMPRESSION, nowrap.
        /// </summary>
        /// <param name="RAWPayload">Content to compress</param>
        /// <param name="ITT">ITT settings, where we'd note the compression algorithm if any.</param>
        /// <returns>Payload for further processing (compressed or not)</returns>
        private static Byte[] TryToCompress(Byte[]                  RAWPayload,
                                            InternalTransportTuple  ITT)
        {

            var inputSize = RAWPayload.Length;

            Byte[] compressedData;

            using (var compressedStream = new MemoryStream())
            {

                using (var deflateStream = new DeflateStream(compressedStream, CompressionLevel.SmallestSize))
                {
                    deflateStream.Write(RAWPayload, 0, RAWPayload.Length);
                }

                compressedData = compressedStream.ToArray();

            }

            if (compressedData.Length < inputSize)
            {
                //itt.cryptoSettings.setCompressionOID(COMPRESSION_GZIP.getOID());
                return compressedData;
            }
            else
            {
                //itt.cryptoSettings.setCompressionOID(COMPRESSION_NONE.getOID());
                return RAWPayload;
            }

            //var tmp      = new Byte[inputSize];
            //var deflater = new Deflater(Deflater.BEST_COMPRESSION, true); // NB: must set "nowrap"! The header fields are moot, but we may not use checksums.
            //deflater.setInput(rawPayload);
            //deflater.finish();

            //byte[] payload;
            //var outputSize = deflater.deflate(tmp);
            //if (outputSize >= inputSize) // in this case, keep original size
            //{
            //    payload = rawPayload;
            //    //itt.cryptoSettings.setCompressionOID(COMPRESSION_NONE.getOID());
            //}
            //else
            //{
            //    payload = new Byte[outputSize];
            //    Array.Copy(tmp, 0, payload, 0, outputSize);
            //    //itt.cryptoSettings.setCompressionOID(COMPRESSION_GZIP.getOID());
            //}

            //deflater.end();

            //return payload;

        }

        #endregion


    }

}
