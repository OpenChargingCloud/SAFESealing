
#region Usings

using System.IO.Compression;

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
    public static class SAFESeal
    {

        #region (static) InflateZLIBcompressedData(CompressedData)

        /// <summary>
        /// Try to decompress if we've got compressed data.
        /// Using "nowrap" settings, we have neither header nor checksum.
        /// </summary>
        /// <param name="Payload">Data to decompress/inflate</param>
        /// <returns>Decompressed/inflated data</returns>
        public static Byte[] InflateZLIBcompressedData(Byte[] CompressedData)
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

        #region (static) TryToCompress(RAWPayload, ITT)

        /// <summary>
        /// Try to apply ZLIB compression.
        /// Important: Zlib wrapper fields must not be used/sent.
        /// That also implies we always use the same settings in this context: BEST_COMPRESSION, nowrap.
        /// </summary>
        /// <param name="RAWPayload">Content to compress</param>
        /// <param name="ITT">ITT settings, where we'd note the compression algorithm if any.</param>
        /// <returns>Payload for further processing (compressed or not)</returns>
        public static Byte[] TryToCompress(Byte[]                  RAWPayload,
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
