using System.IO.Compression;
using System.Text.RegularExpressions;

using Org.BouncyCastle.Crypto.Parameters;


namespace SAFESealing
{
    public class SAFESeal
    {

        private readonly ICryptoFactory                cryptoFactory;
        private          TransportFormatConverter      formatConverter;
        private          IAsymmetricEncryptionWithIIP  asymmetricLayer;

        public  Boolean  KeyAgreementMode    { get; set; }  // flag shorthand for NONE or ECDHE. later versions may use an enum.
        public  Boolean  CompressionMode     { get; set; }  // flag shorthand for NONE or ZLIB.  later versions may use an enum.



        public void SetKeyAgreementMode(Boolean keyAgreementUsed)
        {
            this.KeyAgreementMode  = keyAgreementUsed;
            this.CompressionMode   = false;
            this.formatConverter   = new TransportFormatConverter();
        }


        public SAFESeal(ICryptoFactory CryptoFactory)
        {

            this.cryptoFactory     = CryptoFactory;
            this.formatConverter   = new TransportFormatConverter();
            this.KeyAgreementMode  = false;
            this.CompressionMode   = false;

        }


        /// <summary>
        /// Seal contents: perform calculation of ephemeral key, padding, encryption, and formatting for transport.
        /// </summary>
        /// <param name="ContentToSeal">payload content for sealed transport</param>
        /// <param name="SenderKey">sender private key (caller's key)</param>
        /// <param name="RecipientKeys">recipient public key(s)</param>
        /// <param name="UniqueID">a unique ID to be provided e.g. from a monotonic counter</param>
        /// <returns>wrapped and sealed message</returns>
        public Byte[] Seal(Byte[]                              ContentToSeal,
                           ECPrivateKeyParameters              SenderKey,
                           IEnumerable<ECPublicKeyParameters>  RecipientKeys,
                           Int64                               UniqueID)
        {

            InternalTransportTuple itt;

            if (KeyAgreementMode)
            {
                asymmetricLayer = new ECDHEWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.AES256ECB);
                itt             = new InternalTransportTuple(true); // ECDHE+AES...
                itt.SetDiversification(UniqueID);
            }
            else
            {
                // lacking a proper API, we do this the factual way:
                var description               = SenderKey.ToString();
                var keyLengthFromDescription  = new Regex(@".+RSA private CRT key,\s+(\d{4})\sbits$", RegexOptions.Multiline);
                var match                     = keyLengthFromDescription.Match(description);

                if (match.Success == false)
                    throw new Exception("Could not determine key size");

                var privateKeyLength = UInt32.Parse(match.Groups[1].Value);
                switch (privateKeyLength)
                {
                    //case 1024: asymmetricLayer = new RSAWithIntegrityPadding(AlgorithmSpecCollection.RSA1024); break;
                    case 2048: asymmetricLayer = new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA2048); break;
                    case 4096: asymmetricLayer = new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA4096); break;
                    default:
                        throw new Exception("Key of unsupported size " + privateKeyLength);
                }

                itt = new InternalTransportTuple(false); // RSA
                itt.CryptoSettings.EncryptionKeySize = privateKeyLength;
                // no diversification needed for direct RSA application

            }

            byte[] payload;
            if (CompressionMode == false)
            {
                payload = ContentToSeal;
            }
            else // if compression is activated, perform compression and set respective flag
            {
                payload = TryToCompress(ContentToSeal, itt);
            }

            // perform asymmetric crypto, symmetric crypto, and padding
            itt.EncryptedData  = asymmetricLayer.PadEncryptAndPackage(payload,
                                                                      RecipientKeys,
                                                                      SenderKey,
                                                                      itt.KeyDiversificationData);

            itt.CryptoIV       = asymmetricLayer.SymmetricIV;

            // format the tuple for transport
            return formatConverter.WrapForTransport(itt);

        }



        /**
           * carefully check the sealing, unseal, and return payload data.
           * performs transport unwrapping, calculation of ephemeral key, decryption, and integrity validation.
           * The most important Exception is the BadPaddingException which signals the integrity validation has failed.
           *
           * @param sealedInput     an array of {@link byte} objects
           * @param recipientKey    a {@link PrivateKey} object
           * @param senderPublicKey a {@link PublicKey} object
           * @return payload data, when everything went OK and the integrity has been validated.
           */
        public Byte[] Reveal(Byte[]                  sealedInput,
                             ECPrivateKeyParameters  recipientKey,
                             ECPublicKeyParameters   senderPublicKey) // is one sender public key enough if several were used in sending?
        {

            var tuple           = formatConverter.UnwrapTransportFormat(sealedInput);
            var compressionOID  = tuple.CryptoSettings.Compression?.OID!;

            if (compressionOID.Equals(AlgorithmSpecCollection.COMPRESSION_GZIP.OID))
                CompressionMode = true;

            else if (compressionOID.Equals(AlgorithmSpecCollection.COMPRESSION_NONE.OID))
                CompressionMode = false; // do nothing, ignore.

            else
                throw new Exception("invalid compression");

            // @IMPROVEMENT for later versions: allow to for a more flexible selection of algorithms.
            if (KeyAgreementMode)
            {
                asymmetricLayer = new ECDHEWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.AES256ECB);
            }
            else
            {
                switch (tuple.CryptoSettings.EncryptionKeySize)
                {
                    //case 1024: asymmetricLayer = new RSAWithIntegrityPadding(AlgorithmSpecCollection.RSA1024); break;
                    case 2048: asymmetricLayer = new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA2048); break;
                    case 4096: asymmetricLayer = new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA4096); break;
                    default: throw new Exception("Specified key size not supported");
                }
            }

            var payload = asymmetricLayer.DecryptAndVerify(tuple.EncryptedData,
                                                           senderPublicKey,
                                                           recipientKey,
                                                           tuple.KeyDiversificationData,
                                                           tuple.CryptoIV);

            if (CompressionMode == true)
                payload = InflateZLIBcompressedData(payload);

            return payload;

        }


        /// <summary>
        /// Try to decompress if we've got compressed data.
        /// Using "nowrap" settings, we have neither header nor checksum.
        /// </summary>
        /// <param name="Payload">Data to decompress/inflate</param>
        /// <returns>Decompressed/inflated data</returns>
        private Byte[] InflateZLIBcompressedData(Byte[] compressedData)
        {

            Byte[] decompressedData;

            using (var compressedStream = new MemoryStream(compressedData))
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


        /*
         * Try to apply ZLIB compression.
         * Important: Zlib wrapper fields must not be used/sent.
         * That also implies we always use the same settings in this context: BEST_COMPRESSION, nowrap.
         * @param rawPayload content to compress
         * @param itt settings, where we'd note the compression algorithm if any.
         * @return payload for further processing (compressed or not)
         * @throws NoSuchAlgorithmException if algorithm lookup fails.
         */
        private static Byte[] TryToCompress(Byte[]                  rawPayload,
                                            InternalTransportTuple  itt)
        {

            var inputSize = rawPayload.Length;

            Byte[] compressedData;

            using (var compressedStream = new MemoryStream())
            {

                using (var deflateStream = new DeflateStream(compressedStream, CompressionLevel.SmallestSize))
                {
                    deflateStream.Write(rawPayload, 0, rawPayload.Length);
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
                return rawPayload;
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

    }

}
