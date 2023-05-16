
#region Usings

using Org.BouncyCastle.Security;

#endregion

namespace SAFESealing
{

    //ToDo(ahzf): Check BIG_ENDIAN vs. LITTLE_ENDIAN!

    /// <summary>
    /// Core logic for the Integrity Padding with Nonce process:
    /// Apply / Verify the padding.
    /// 
    /// Implementation limitations:
    ///  - java.lang.Integer.MAX_SIZE = 2 GB-1 maximum ciphertext length;
    ///  - accordingly, the plaintext must be even shorter.
    ///  - minimum cipherBlockSize is 9, but 16 is the lowest realistic value.
    /// </summary>
    public class InterleavedIntegrityPadding
    {

        #region Data

        private static readonly Byte[]         MAGIC_ID_VERSION_1_0   = { 0x3e, 0x7a, 0xb1, 0x70, 0x5a, 0xfe, 0xe4, 0x10 }; // 0x3E7AB1705AFEE410;
        private static readonly UInt32         MAGIC_ID_LENGTH        = 8;
        public  static readonly UInt32         NONCE_SIZE             = 4; // 4 byte.
        private static readonly UInt32         PAYLOAD_LENGTH_SIZE    = 4; // 4 byte.

        private        readonly SecureRandom   rng;
        private        readonly UInt32         payloadBytesPerBlock;
        private        readonly UInt32         cipherBlockSize;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="cipherBlockSize">
        /// required parameter: size of the cipher blocks, in byte.
        /// common sizes like 128/192/256 bit (16/25/32 byte) are supported.
        /// shorter blocks like 8 byte are not supported by this implementation, though possible in theory (shortening nonce and payload length size).</param>
        public InterleavedIntegrityPadding(UInt32 CipherBlockSize)
        {

            if (CipherBlockSize < NONCE_SIZE + PAYLOAD_LENGTH_SIZE + 1) // we need at least this number of bytes.
                throw new Exception("cipher block size too small"); // DES e.g. is not acceptable.

            this.cipherBlockSize       = CipherBlockSize;
            this.payloadBytesPerBlock  = CipherBlockSize - NONCE_SIZE;
            this.rng                   = new SecureRandom();

        }

        #endregion


        #region PerformPadding(Payload)

        /// <summary>
        /// Perform the Integrity Padding on the given payload.
        /// </summary>
        /// <param name="Payload">Input data for the padding.</param>
        public ByteArray PerformPadding(Byte[] Payload)
        {

            var bufferSizeRequiredLong = CalculateNumberOfBytesOverall((UInt32) Payload.Length,
                                                                       cipherBlockSize);

            if (bufferSizeRequiredLong > Int32.MaxValue)
                return ByteArray.Error($"The gieven payload is too large. Its maximum size in byte is {Int32.MaxValue}!");

            using var paddedDataStream = new MemoryStream(new Byte[(Int32) bufferSizeRequiredLong]);
            //paddedDataStream.order(ByteOrder.BIG_ENDIAN); // Network byte order defined.


            #region Write Interleaved Integrity Padding header

            // Write MAGIC ID, shortened if needed.
            var magicIdLengthRequired = CalculateMagicIdSizeUsed();
            paddedDataStream.Write(MAGIC_ID_VERSION_1_0, 0, (Int32) magicIdLengthRequired);

            // Add R0 padding.
            var randomBytes             = new Byte[1];
            var numHeaderPaddingBytes   = cipherBlockSize - (magicIdLengthRequired + NONCE_SIZE + PAYLOAD_LENGTH_SIZE);
            while (numHeaderPaddingBytes>0)
            {
                rng.NextBytes(randomBytes);
                paddedDataStream.WriteByte(randomBytes[0]);
                numHeaderPaddingBytes--;
            }

            // we can't use padToBlockSizeWithRandom here since we pad R0 in the *middle* of the header block.

            // Write the nonce
            // Always written at offset cipherBlockSize - (NONCE_SIZE + PAYLOAD_LENGTH_SIZE)
            var nonce = new Byte[NONCE_SIZE];
            rng.NextBytes(nonce);
            var nonceWithCounter        = BitConverter.ToUInt32(nonce, 0);
            paddedDataStream.Write(nonce);

            // Write the length of the payload to be reconstructed at recipient side.
            // Always written at offset cipherBlockSize - PAYLOAD_LENGTH_SIZE
            paddedDataStream.Write(BitConverter.GetBytes(Payload.Length));
            //assert (bb.position()==cipherBlockSize); // implementation check: header block exactly complete?

            #endregion

            #region Write payload data

            for (var offset = 0U; offset < Payload.Length; offset += payloadBytesPerBlock)
            {

                // pre-increment (not post)
                nonceWithCounter++;

                // java.lang.Math.toIntExact would fail here at wraparound. We have to perform this cast ourselves:
                // Place 4 byte integer counter CTR first.
                paddedDataStream.Write(BitConverter.GetBytes((Int32) (nonceWithCounter & 0x0FFFFFFFFL)));

                // Wenn wir dem ende des blocks näher kommen...
                var remainder = Payload.Length - offset;
                paddedDataStream.Write(Payload,
                                       (Int32) offset,
                                       (Int32) Math.Min(remainder, payloadBytesPerBlock));

            }

            #endregion

            #region Write padding data

            // When the last block needs padding, apply it here...
            PadToBlockSizeWithRandom(paddedDataStream);

            // Check if remainder != 0
            if (Payload.Length % payloadBytesPerBlock == 0) // perfect match means trailing block
            {

                // Append trailing block; only necessary if the r1 was empty
                nonceWithCounter++;

                //@CHECK the java Math.toIntExact() function on signedness. we want an unsigned wrap-around, that's why we use long and Math.toIntExact().
                // Place 4 byte integer counter CTR.
                paddedDataStream.Write(BitConverter.GetBytes((Int32) (nonceWithCounter & 0x0FFFFFFFFL)));

                // fill up
                PadToBlockSizeWithRandom(paddedDataStream);

            }

            #endregion

            // With clean block input, this should equal block length
            // Return number of bytes used
            return ByteArray.Ok(paddedDataStream.ToArray());

        }

        #endregion

        #region VerifyAndExtract(PaddedData)

        /// <summary>
        /// Verify the Interleaved Integrity Padding, and extract payload data.
        /// </summary>
        /// <param name="PaddedData">Data to perform validation on.</param>
        public ByteArray VerifyAndExtract(Byte[] PaddedData)
        {

            #region Data

            if (PaddedData.Length == 0)
                return ByteArray.Error("Invalid padded data!");

            if (PaddedData.Length % cipherBlockSize != 0)
                return ByteArray.Error("Invalid padded data!");

            var success           = true;
            var magicId           = new Byte[MAGIC_ID_LENGTH];
            var nonce             = new Byte[NONCE_SIZE];
            var lengthBuffer      = new Byte[PAYLOAD_LENGTH_SIZE];
            var devNull           = new Byte[1];
            var int32Buffer       = new Byte[4];
            var paddedDataStream  = new MemoryStream(PaddedData);
            //paddedDataStream.order(ByteOrder.BIG_ENDIAN);

            #endregion

            try
            {

                #region 1. Read and verify MAGIC ID

                var magicIdLengthExpected   = CalculateMagicIdSizeUsed();
                var numHeaderPaddingBytes   = cipherBlockSize - (magicIdLengthExpected + NONCE_SIZE + PAYLOAD_LENGTH_SIZE);

                paddedDataStream.Read(magicId, 0, (Int32) magicIdLengthExpected);

                if (CompareBytes(magicId, MAGIC_ID_VERSION_1_0, magicIdLengthExpected) == false)
                    return ByteArray.Error("Format error!");

                #endregion

                #region 2. Skip padding bytes

                while (numHeaderPaddingBytes > 0)
                {
                    paddedDataStream.Read(devNull);
                    numHeaderPaddingBytes--;
                }

                #endregion

                #region 3. Read Nonce

                paddedDataStream.Read(nonce);
                var nonceCounter           = BitConverter.ToUInt32(nonce,        0);

                #endregion

                #region 4. Read payload length, implementation limit 4 GB
                //    Maybe we have to quit early, since we cannot predict the number of subsequent blocks correctly!

                paddedDataStream.Read(lengthBuffer);
                var payloadLength          = BitConverter.ToUInt32(lengthBuffer, 0);

                if (payloadLength >= PaddedData.Length)
                    return ByteArray.Error($"Payload length {payloadLength} >= PaddedData length {PaddedData.Length}!");

                var expectedPayloadBlocks  = CalculateNumberOfPayloadBlocks(payloadLength,
                                                                            payloadBytesPerBlock);

                #endregion

                #region 5. Loop through all expected blocks

                var payloadBuffer          = new Byte[payloadLength];
                var payloadOffset          = 0U;

                for (var i = 0; i<expectedPayloadBlocks; i++)
                {

                    nonceCounter++;
                    paddedDataStream.Read(int32Buffer);
                    var givenCounterValue  = BitConverter.ToUInt32(int32Buffer);

                    if (givenCounterValue != nonceCounter)
                        success = false; // foil timing attacks here by not exiting right away.

                    // copy payload data over
                    var remainder = payloadLength - payloadOffset;
                    paddedDataStream.Read(payloadBuffer,
                                          (Int32) payloadOffset,
                                          (Int32) (remainder > payloadBytesPerBlock
                                                       ? payloadBytesPerBlock
                                                       : remainder));

                    payloadOffset += payloadBytesPerBlock;

                }

                #endregion

                #region 6. Check whether to expect a trailing block or not

                if (payloadLength % payloadBytesPerBlock == 0) // perfect match means trailing block
                {

                    // 8. Skip optional padding to next block start
                    SkipToBlockSize(paddedDataStream);

                    // 9. Check trailing nonce copy to match to the heading one.
                    nonceCounter++;
                    paddedDataStream.Read(int32Buffer);
                    var givenCounterValue  = BitConverter.ToUInt64(int32Buffer);

                    if (givenCounterValue != nonceCounter)
                        success = false; // foil timing attacks here by not exiting right away.

                    // 10. Omit/ignore trailing random data after that.
                    SkipToBlockSize(paddedDataStream); // not needed for validation, just to access the bytes in memory

                }

                #endregion

                #region 7. Plausibility checks

                // Whether we've accurately reached the end.
                if (payloadOffset < payloadLength)
                    success = false;

                // Whether the remaining # of bytes is less than blocksize. otherwise, something's off.
                if (paddedDataStream.Position % cipherBlockSize > payloadBytesPerBlock)
                    success = false;

                #endregion

                if (!success)
                    return ByteArray.Error("Something wicked happened!");

                return ByteArray.Ok(payloadBuffer);

            }
            catch (Exception e)
            {
                // integer overflow from Math.toIntExact if one of those values is corrupted
                return ByteArray.Exception(e);
            }

        }

        #endregion


        // Helper methods

        #region (private) PadToBlockSizeWithRandom(ByteBuffer)

        /// <summary>
        /// Pad to cipher block size, filling with random data.
        /// </summary>
        /// <param name="ByteBuffer">handle for byte array, with numerical position cursor (offset)</param>
        private void PadToBlockSizeWithRandom(MemoryStream ByteBuffer)
        {

            // fill up to block size with random data.
            var currentDiff  = CalculatePadding((UInt32) ByteBuffer.Position,
                                                cipherBlockSize);

            var randomBytes  = new Byte[1];

            // if not at block boundary, fill with random data.
            while (currentDiff != 0)
            {
                rng.       NextBytes(randomBytes);
                ByteBuffer.WriteByte(randomBytes[0]);
                currentDiff--;
            }

        }

        #endregion

        #region (private) SkipToBlockSize(ByteBuffer)

        /// <summary>
        /// In a byte buffer, skip ahead to the next block boundary.
        /// </summary>
        /// <param name="ByteBuffer">ByteBuffer for which to do this.</param>
        private void SkipToBlockSize(MemoryStream ByteBuffer)
        {

            var currentDiff = CalculatePadding((UInt32) ByteBuffer.Position,
                                               cipherBlockSize);

            // if not at block boundary, fill with random data.
            while (currentDiff != 0)
            {
                ByteBuffer.ReadByte();
                currentDiff--;
            }

        }

        #endregion

        #region (private) CalculateMagicIdSizeUsed()

        /// <summary>
        /// Calculate number of bytes from the MAGIC ID value to be used in given circumstances.
        /// </summary>
        private UInt32 CalculateMagicIdSizeUsed()
        {

            var headerPad = (Int32) (cipherBlockSize - (MAGIC_ID_LENGTH + NONCE_SIZE + PAYLOAD_LENGTH_SIZE));

            if (headerPad == 0) // a perfect match would leave no space for the R0, so we shorten the ID by 1.
                headerPad = -1;

            return headerPad < 0
                       ? (UInt32) (MAGIC_ID_LENGTH + headerPad)  // shortened
                       : MAGIC_ID_LENGTH;                        // full length

        }

        #endregion

        #region (private) CalculateNumberOfBytesOverall (PayloadLengthInBytes, CipherBlockSize)

        /// <summary>
        /// Calculate the buffer size.
        /// </summary>
        /// <param name="PayloadLengthInBytes">How many bytes of payload data are to be protected and encrypted</param>
        /// <param name="CipherBlockSize">how many bytes fit in a crypto algorithm block</param>
        public static UInt64 CalculateNumberOfBytesOverall(UInt32 PayloadLengthInBytes,
                                                           UInt32 CipherBlockSize)

            => CipherBlockSize * CalculateNumberOfBlocksOverall(PayloadLengthInBytes,
                                                                CipherBlockSize - NONCE_SIZE);

        #endregion

        #region (private) CalculateNumberOfBlocksOverall(PayloadLengthInBytes, PayloadBytesPerBlock)

        /// <summary>
        /// Return the number of required block: IIP Header Block + Data Blocks.
        /// 
        /// This implementation prefers legibility to efficiency.
        /// Compilers will be able to optimise this nicely.
        /// </summary>
        /// <param name="PayloadLengthInBytes">The payload length in bytes.</param>
        /// <param name="PayloadBytesPerBlock">The payload bytes per block.</param>
        private static UInt32 CalculateNumberOfBlocksOverall(UInt32 PayloadLengthInBytes,
                                                             UInt32 PayloadBytesPerBlock)

            => 1 + CalculateNumberOfPayloadBlocks(PayloadLengthInBytes + NONCE_SIZE,
                                                  PayloadBytesPerBlock);

        #endregion

        #region (private) CalculateNumberOfPayloadBlocks(PayloadLengthInBytes, PayloadBytesPerBlock)

        /// <summary>
        /// Calculate number of payload blocks.
        /// </summary>
        /// <param name="PayloadLengthInBytes">The payload length in bytes.</param>
        /// <param name="PayloadBytesPerBlock">The payload bytes per block.</param>
        private static UInt32 CalculateNumberOfPayloadBlocks(UInt32 PayloadLengthInBytes,
                                                             UInt32 PayloadBytesPerBlock)

            => (PayloadLengthInBytes + CalculatePadding(PayloadLengthInBytes,
                                                        PayloadBytesPerBlock)) / PayloadBytesPerBlock;

        #endregion

        #region (private) CalculatePadding(Number, Alignment)

        /// <summary>
        /// Calculate the number of additional padding elements
        /// that need to be added to be aligned with the alignment value.
        /// </summary>
        /// <param name="Number">The current value.</param>
        /// <param name="Alignment">The boundary it is to be aligned with.</param>
        private static UInt32 CalculatePadding(UInt32 Number,
                                               UInt32 Alignment)
        {

            var diff = Number % Alignment;

            return diff != 0
                       ? Alignment - diff
                       : 0;

        }

        #endregion

        #region (private) CompareBytes(Array1, Array2, MaxBytesToCompare)

        /// <summary>
        /// Compare the given byte arrays.
        /// </summary>
        /// <param name="Array1">The first array of bytes for comparison</param>
        /// <param name="Array2">The second array of bytes for comparison</param>
        /// <param name="MaxBytesToCompare">The number of bytes to compare.</param>
        private static Boolean CompareBytes(Byte[] Array1,
                                            Byte[] Array2,
                                            UInt32 MaxBytesToCompare)
        {

            if (Array1.Length != Array2.Length)
                return false;

            for (var i = 0U; i < MaxBytesToCompare; i++)
            {
                if (Array1[i] != Array2[i])
                    return false;
            }

            return true;

        }

        #endregion

        #region (private) CompareBytes(Array1, Offset1, Array2, Offset2, MaxBytesToCompare)

        /// <summary>
        /// Compare the given byte arrays.
        /// </summary>
        /// <param name="Array1">The first array of bytes for comparison</param>
        /// <param name="Offset1">The offset where to start in the first byte array</param>
        /// <param name="Array2">The second array of bytes for comparison</param>
        /// <param name="Offset2">The offset where to start in the second byte array</param>
        /// <param name="MaxBytesToCompare">The number of bytes to compare.</param>
        private static Boolean CompareBytes(Byte[]  Array1,
                                            UInt32  Offset1,
                                            Byte[]  Array2,
                                            UInt32  Offset2,
                                            UInt32  MaxBytesToCompare)
        {

            if (Offset1 + MaxBytesToCompare > Array1.Length ||
                Offset2 + MaxBytesToCompare > Array2.Length)
            {
                return false;
            }

            for (var i = 0U; i < MaxBytesToCompare; i++)
            {
                if (Array1[Offset1 + i] != Array2[Offset2 + i])
                    return false;
            }

            return true;

        }

        #endregion


    }

}
