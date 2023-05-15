
namespace SAFESealing
{

    /// <summary>
    /// Shared code.
    /// </summary>
    public static class SharedCode
    {

        #region CalculateNumberOfPayloadBlocks(PayloadLengthInBytes, PayloadBytesPerBlock)

        /// <summary>
        /// Calculate number of payload blocks.
        /// </summary>
        /// <param name="PayloadLengthInBytes">The payload length in bytes.</param>
        /// <param name="PayloadBytesPerBlock">The payload bytes per block.</param>
        public static UInt32 CalculateNumberOfPayloadBlocks(UInt32 PayloadLengthInBytes,
                                                            UInt32 PayloadBytesPerBlock)
        {

            var paddedDataBytes = PayloadLengthInBytes + CalculatePadding(PayloadLengthInBytes,
                                                                          PayloadBytesPerBlock);

            return paddedDataBytes / PayloadBytesPerBlock;

        }

        #endregion

        #region CalculatePadding(Number, Alignment)

        /// <summary>
        /// Calculate the number of additional padding elements
        /// that need to be added to be aligned with the alignment value.
        /// </summary>
        /// <param name="Number">The current value.</param>
        /// <param name="Alignment">The boundary it is to be aligned with.</param>
        public static UInt32 CalculatePadding(UInt32 Number,
                                              UInt32 Alignment)
        {

            var diff = Number % Alignment;

            return diff != 0
                       ? Alignment - diff
                       : 0;

        }

        #endregion

        #region CompareBytes(Array1, Array2, MaxBytesToCompare)

        /// <summary>
        /// Compare the given byte arrays.
        /// </summary>
        /// <param name="Array1">The first array of bytes for comparison</param>
        /// <param name="Array2">The second array of bytes for comparison</param>
        /// <param name="MaxBytesToCompare">The number of bytes to compare.</param>
        public static Boolean CompareBytes(Byte[] Array1,
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

        #region CompareBytes(Array1, Offset1, Array2, Offset2, MaxBytesToCompare)

        /// <summary>
        /// Compare the given byte arrays.
        /// </summary>
        /// <param name="Array1">The first array of bytes for comparison</param>
        /// <param name="Offset1">The offset where to start in the first byte array</param>
        /// <param name="Array2">The second array of bytes for comparison</param>
        /// <param name="Offset2">The offset where to start in the second byte array</param>
        /// <param name="MaxBytesToCompare">The number of bytes to compare.</param>
        public static Boolean CompareBytes(Byte[]  Array1,
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
