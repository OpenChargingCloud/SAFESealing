using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SAFESealing
{

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

        private static readonly Byte[]        MAGIC_ID_VERSION_1_0 = { 0x3e, 0x7a, (byte) 0xb1, 0x7C, 0x5A, (byte) 0xFE, (byte) 0xE4, 0x10 }; // 0x3e7ab1705AFEE410L;
        private static readonly Int32         MAGIC_ID_LENGTH      = 8;
        public  static readonly Int32         NONCE_SIZE           = 4; // 4 byte.
        private static readonly Int32         PAYLOAD_LENGTH_SIZE  = 4; // 4 byte.

        private readonly        SecureRandom  rng;
        private readonly        Int32         payloadBytesPerBlock;
        private readonly        Int32         cipherBlockSize;


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="cipherBlockSize">
        /// required parameter: size of the cipher blocks, in byte.
        /// common sizes like 128/192/256 bit (16/25/32 byte) are supported.
        /// shorter blocks like 8 byte are not supported by this implementation, though possible in theory (shortening nonce and payload length size).</param>
        public InterleavedIntegrityPadding(Int32 CipherBlockSize)
        {

            if (CipherBlockSize < NONCE_SIZE + PAYLOAD_LENGTH_SIZE + 1) // we need at least this number of bytes.
                throw new Exception("cipher block size too small"); // DES e.g. is not acceptable.

            this.cipherBlockSize       = CipherBlockSize;
            this.payloadBytesPerBlock  = CipherBlockSize - NONCE_SIZE;
            this.rng                   = new SecureRandom();

        }



        /// <summary>
        /// Get input, produce output - allocating a temporary buffer for it.
        /// </summary>
        /// <param name="Payload">payload data to perform integrity padding on</param>
        /// <returns>the padded data.</returns>
        public Byte[] PerformPaddingWithAllocation(Byte[] Payload)
        {

            var bufferSizeRequiredLong = CalculateNumberOfBytesOverall(Payload.Length,
                                                                       this.cipherBlockSize);

            if (bufferSizeRequiredLong > Int32.MaxValue)
                throw new Exception($"payload too large, maximum size in byte is {Int32.MaxValue}!");

            if (bufferSizeRequiredLong <= 0)
                throw new Exception($"payload too small!");

            var buffer = new Byte[(Int32) bufferSizeRequiredLong];

            PerformPaddingInPlace(Payload, buffer);

            return buffer;

        }

        /// <summary>
        /// Perform the Integrity Padding.
        /// </summary>
        /// <param name="Input">input data for the padding</param>
        /// <param name="OutputBuffer">buffer to place padded data into. Must be allocated to the correct size!</param>
        /// <returns>number of bytes used in the buffer. For a correctly allocated buffer, this will be equal to the buffer size.</returns>
        Int64 PerformPaddingInPlace(Byte[] Input,
                                    Byte[] OutputBuffer)
        {

            // check input parameters
            //assert (input        != null);
            //assert (outputBuffer != null);

            // prepare the protection nonce
            var nonce = new Byte[NONCE_SIZE];
            rng.NextBytes(nonce);

            var nonceWithCounter = SharedCode.Get4ByteUnsignedIntFromBuffer(nonce, 0); // optimisation: instead of modulating the value every time on the nonce value.

            // prepare the buffer
            using (var bb = new MemoryStream(OutputBuffer))
            {

                //bb.order(ByteOrder.BIG_ENDIAN); // network byte order defined.
                //if (bb.hasArray()==false)
                //    throw new UnsupportedOperationException("something's really wrong with the ByteBuffer in this JRE");

                // heading ("header") block
                // write ID, shortened if need be.
                var idSizeUsed = CalculateIDsizeUsed();
                bb.Write(MAGIC_ID_VERSION_1_0, 0, idSizeUsed);


                var randomBytes = new Byte[1];

                // add R0 padding.
                var numHeaderPaddingBytes = cipherBlockSize - (idSizeUsed + NONCE_SIZE + PAYLOAD_LENGTH_SIZE);
                while (numHeaderPaddingBytes>0)
                {
                    rng.NextBytes(randomBytes);
                    bb.WriteByte(randomBytes[0]);
                    numHeaderPaddingBytes--;
                }

                // we can't use padToBlockSizeWithRandom here since we pad R0 in the *middle* of the header block.

                // write the nonce
                bb.Write(nonce); // always written at offset cipherBlockSize - (NONCE_SIZE + PAYLOAD_LENGTH_SIZE)

                // write the length of the payload to be reconstructed at recipient side.
                var ll = BitConverter.GetBytes(Input.Length);
                bb.Write(ll); // always written at offset cipherBlockSize - PAYLOAD_LENGTH_SIZE
                //assert (bb.position()==cipherBlockSize); // implementation check: header block exactly complete?
                // header block complete.

                // now loop through input data and place it to the buffer
                int offset;
                for (offset = 0; offset<Input.Length; offset += payloadBytesPerBlock)
                {

                    // pre-increment (not post)
                    nonceWithCounter++;

                    // java.lang.Math.toIntExact would fail here at wraparound. We have to perform this cast ourselves:
                    var ll2 = BitConverter.GetBytes((Int32)(nonceWithCounter & 0x0FFFFFFFFL));
                    bb.Write(ll2); // place 4 byte integer counter CTR first.

                    // wenn wir dem ende des blocks näher kommen...
                    var remainder = Input.Length-offset;
                    bb.Write(Input,
                             offset,
                             Math.Min(remainder, payloadBytesPerBlock));

                }

                // if last block needs padding, apply it here
                PadToBlockSizeWithRandom(bb);

                // check if remainder != 0
                if (Input.Length % payloadBytesPerBlock == 0) // perfect match means trailing block
                {

                    // append trailing block; only necessary if the r1 was empty
                    nonceWithCounter++;

                    //@CHECK the java Math.toIntExact() function on signedness. we want an unsigned wrap-around, that's why we use long and Math.toIntExact().
                    var ll3 = BitConverter.GetBytes((Int32) (nonceWithCounter & 0x0FFFFFFFFL));
                    bb.Write(ll3); // place 4 byte integer counter CTR.
                    PadToBlockSizeWithRandom(bb); // fill up

                }

                // with clean block input, this should equal block length
                return bb.Position; // number of bytes used

            }

        }

        /**
         * core IIP function: validate the Integrity Padding, and extract payload data.
         *
         * @param paddedData data to perform validation on.
         * @return extracted payload data.
         * @throws javax.crypto.BadPaddingException      in all cases where the validation fails.
         * @throws java.lang.IllegalArgumentException if the buffer supplied is of incorrect size. added to aid implementation checks.
         *                                  no security relevance since an attacker would know the cipher block size anyhow.
         */
        public Byte[] CheckAndExtract(Byte[] PaddedData)
        {

            // guard clause
            if (PaddedData.Length % cipherBlockSize != 0)
                throw new Exception("buffer size invalid");

            // preparition of local variables
            var id                      = new Byte[MAGIC_ID_LENGTH];
            var nonce                   = new Byte[NONCE_SIZE];
            var nonce2                  = new Byte[NONCE_SIZE];
            var lengthBuffer            = new Byte[PAYLOAD_LENGTH_SIZE];
            Byte[] payloadBuffer        = null;
            var idLengthExpected        = CalculateIDsizeUsed();
            var numHeaderPaddingBytes   = cipherBlockSize-(idLengthExpected+NONCE_SIZE+PAYLOAD_LENGTH_SIZE);
            Boolean success = true;

            var devNull      = new Byte[1];
            var int32Buffer  = new Byte[4];

            var bb = new MemoryStream(PaddedData);
            //bb.order(ByteOrder.BIG_ENDIAN);

            try
            {

                // 1. start reading
                bb.Read(id, 0, idLengthExpected);
                while (numHeaderPaddingBytes>0)
                {
                    bb.Read(devNull); // skip
                    numHeaderPaddingBytes--;
                }
                bb.Read(nonce);
                bb.Read(lengthBuffer);
                var payloadLength = (Int32) SharedCode.Get4ByteUnsignedIntFromBuffer(lengthBuffer, 0); // implementation limit 2GB

                // 2. check ID
                if (SharedCode.CompareBytes(id, 0, MAGIC_ID_VERSION_1_0, 0, idLengthExpected) == false)
                    success = false;
                // early exit possible.

                // 3. convert and check length
                // first rough check
                if (payloadLength>=PaddedData.Length)
                    throw new Exception(); // in this case, we have to quit early, since we cannot predict the number of subsequent blocks correctly

                var expectedPayloadBlocks  = SharedCode.CalculateNumberOfPayloadBlocks(payloadLength, payloadBytesPerBlock);
                //@IMPROVEMENT different calculation allowing us to delay the exit, eg. from overall length and cipherBlockSize

                // 3. get nonce counter ready
                var nonceCounter           = (UInt64) SharedCode.Get4ByteUnsignedIntFromBuffer(nonce, 0);

                // 4. prepare output buffer. -- for supplied buffers, there is a requirement of minimum size to be checked.
                payloadBuffer = new Byte[payloadLength];

                // 5. loop through all expected blocks
                var payloadOffset = 0;
                for (var i = 0; i<expectedPayloadBlocks; i++)
                {

                    nonceCounter++;
                    bb.Read(int32Buffer);
                    var givenCounterValue = BitConverter.ToUInt32(int32Buffer);

                    if (givenCounterValue != nonceCounter)
                        success = false; // foil timing attacks here by not exiting right away.

                    // copy payload data over
                    var remainder = payloadLength - payloadOffset;
                    bb.Read(payloadBuffer,
                            payloadOffset,
                            remainder > payloadBytesPerBlock
                                ? payloadBytesPerBlock
                                : remainder);

                    payloadOffset += payloadBytesPerBlock;

                }

                // check whether to expect a trailing block or not

                if (payloadLength % payloadBytesPerBlock == 0) // perfect match means trailing block
                {

                    // 6. skip optional padding to next block start
                    SkipToBlockSize(bb);

                    // 7. check trailing nonce copy to match to the heading one.
                    nonceCounter++;
                    bb.Read(int32Buffer);
                    var givenCounterValue = BitConverter.ToUInt64(int32Buffer);

                    if (givenCounterValue != nonceCounter)
                        success = false; // foil timing attacks here by not exiting right away.

                    // 8. omit/ignore trailing random data after that.
                    SkipToBlockSize(bb); // not needed for validation, just to access the bytes in memory

                }

                // plausibility check whether we've accurately reached the end.
                if (payloadOffset < payloadLength)
                    success = false;

                // plausibility check whether the remaining # of bytes is less than blocksize. otherwise, something's off.
                //if (bb.hasArray()) // arrayOffset is available only if this is given.
                //{
                //    if (bb.arrayOffset()%cipherBlockSize>payloadBytesPerBlock)
                //        success = false;
                //}

            }

            catch (Exception e)
            {
                Debug.WriteLine(e);
                success = false; //integer overflow from Math.toIntExact if one of those values is corrupted
            }

            // 8. result: OK or failure.
            if (success != true)
                throw new Exception();

            return payloadBuffer;

        }



        /// <summary>
        /// Pad to cipher block size, filling with random data.
        /// </summary>
        /// <param name="ByteBuffer">handle for byte array, with numerical position cursor (offset)</param>
        private void PadToBlockSizeWithRandom(MemoryStream ByteBuffer)
        {

            // fill up to block size with random data.
            var currentOffset  = (Int32) ByteBuffer.Position;
            var currentDiff    = SharedCode.CalculatePadding(currentOffset,
                                                             cipherBlockSize);

            var randomBytes = new Byte[1];
            while (currentDiff != 0) // if not at block boundary, fill with random data.
            {
                rng.       NextBytes(randomBytes);
                ByteBuffer.WriteByte(randomBytes[0]);
                currentDiff--;
            }

        }

        /// <summary>
        /// In a byte buffer, skip ahead to the next block boundary.
        /// </summary>
        /// <param name="ByteBuffer">ByteBuffer for which to do this.</param>
        private void SkipToBlockSize(MemoryStream ByteBuffer)
        {

            var currentOffset  = (Int32) ByteBuffer.Position;
            var currentDiff    = SharedCode.CalculatePadding(currentOffset,
                                                             cipherBlockSize);

            while (currentDiff != 0) // if not at block boundary, fill with random data.
            {
                ByteBuffer.ReadByte();
                currentDiff--;
            }

        }

        /// <summary>
        /// Calculate number of bytes from the ID value to be used in given circumstances.
        /// </summary>
        /// <returns>Number of ID bytes to be used.</returns>
        private Int32 CalculateIDsizeUsed()
        {

            var headerPad = cipherBlockSize - (MAGIC_ID_LENGTH + NONCE_SIZE + PAYLOAD_LENGTH_SIZE);

            if (headerPad == 0) // a perfect match would leave no space for the R0, so we shorten the ID by 1.
                headerPad = -1;

            return headerPad < 0
                       ? MAGIC_ID_LENGTH + headerPad    // shortened
                       : MAGIC_ID_LENGTH;               // full length

        }

        /// <summary>
        /// Calculate the buffer size.
        /// </summary>
        /// <param name="payloadLengthInBytes">How many bytes of payload data are to be protected and encrypted</param>
        /// <param name="cipherBlockSize">how many bytes fit in a crypto algorithm block</param>
        /// <returns>the required buffer size, in byte</returns>
        public static Int64 CalculateNumberOfBytesOverall(Int32 payloadLengthInBytes,
                                                          Int32 cipherBlockSize)
        {

            var payloadBytesPerBlock = cipherBlockSize - NONCE_SIZE;

            return (long)cipherBlockSize * (long) CalculateNumberOfBlocksOverall(payloadLengthInBytes, payloadBytesPerBlock);

        }

        /// <summary>
        /// This implementation prefers legibility to efficiency.
        /// Compilers will be able to optimise this nicely
        /// </summary>
        /// <param name="payloadLengthInBytes"></param>
        /// <param name="payloadBytesPerBlock"></param>
        /// <returns></returns>
        private static Int32 CalculateNumberOfBlocksOverall(Int32 payloadLengthInBytes,
                                                            Int32 payloadBytesPerBlock)
        {

            var numberOfDataBlocks  = SharedCode.CalculateNumberOfPayloadBlocks(payloadLengthInBytes + NONCE_SIZE, payloadBytesPerBlock);
            var numberOfBlocks      = 1 + numberOfDataBlocks; // header block + data blocks

            return numberOfBlocks;

        }


    }

}
