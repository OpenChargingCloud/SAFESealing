using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SAFESealing
{
    public class SharedCode
    {

        /**
         * <p>calculateNumberOfPayloadBlocks.</p>
         *
         * @param payloadLengthInBytes a int
         * @param payloadBytesPerBlock a int
         * @return a int
         */
        public static int CalculateNumberOfPayloadBlocks(int payloadLengthInBytes, int payloadBytesPerBlock)
        {
            int paddedDataBytes = payloadLengthInBytes + CalculatePadding(payloadLengthInBytes, payloadBytesPerBlock);
            int numberOfDataBlocks = paddedDataBytes / payloadBytesPerBlock;
            return numberOfDataBlocks;
        }

        /**
         * calculate padding required
         * @param number    the current value
         * @param alignment the boundary it is to be aligned with
         * @return the number of additional padding elements that need to be added to be aligned with the alignment value.
         */
        public static int CalculatePadding(int number, int alignment)
        {
            int diff = (number % alignment);
            return (diff != 0) ? alignment - diff : 0;
        }

        /**
         * read a 4-byte unsigned int from a buffer.
         * Precondition: there's at least 4 bytes after offset. No explicit check here, may throw IndexOutOfBoundsException.
         *
         * @param input  byte array to read from
         * @param offset starting offset in byte array
         * @return the unsigned int, placed in a long (since Java doesn't allow unsigned values).
         */
        public static long Get4ByteUnsignedIntFromBuffer(byte[] input, int offset)
        {
            var tmpReader = new MemoryStream(input);
            //tmpReader.order(ByteOrder.BIG_ENDIAN);

            var ll        = new Byte[4];
            tmpReader.Read(ll, offset, 4);
            var intValue  = BitConverter.ToInt32(ll);
            return (long) (uint) intValue; // wordy version of (intValue & 0x00000000ffffffffL)

        }

        /**
         * <p>write8ByteUnsignedLongToBuffer.</p>
         *
         * @param value a {@link java.lang.Long} object
         * @param buffer an array of {@link byte} objects
         */
        public static void Write8ByteUnsignedLongToBuffer(long value, byte[] buffer)
        {
            //assert(buffer.length >= Long.BYTES);
            var wrap = new MemoryStream(buffer);
            //wrap.order(ByteOrder.BIG_ENDIAN);
            var vb = BitConverter.GetBytes(value);
            wrap.Write(vb);
        }

        /**
         * copy from metabit library
         * byte array compare.
         * NB: no size checks are performed here.
         * For whatever reason, Java System has an arrayCopy, but no arrayCompare.
         *
         * @param sourceA first array of bytes for comparison
         * @param offsetInA offset where to start in the first byte array
         * @param sourceB second array of bytes for comparison
         * @param offsetInB offset where to start in the second byte array
         * @param maxBytesToCompare number of bytes to compare.
         * @return true if all bytes were equal.
         */
        public static Boolean CompareBytes(Byte[]  sourceA,
                                           Int32   offsetInA,
                                           Byte[]  sourceB,
                                           Int32   offsetInB,
                                           Int32   maxBytesToCompare)
        {

            for (var i = 0; i < maxBytesToCompare; i++)
            {
                if (sourceA[offsetInA + i] != sourceB[offsetInB + i])
                    return false;
            }

            return true;

        }

    }

}
