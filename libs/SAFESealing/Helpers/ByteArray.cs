

namespace SAFESealing
{

    /// <summary>
    /// A byte array with an optional error message.
    /// </summary>
    public readonly struct ByteArray : IEquatable<ByteArray>,
                                       IComparable<ByteArray>,
                                       IComparable
    {

        #region Properties

        /// <summary>
        /// The data of the byte array.
        /// </summary>
        public Byte[]  Data            { get; }

        /// <summary>
        /// An optional error message.
        /// </summary>
        public String  ErrorMessage    { get; }

        /// <summary>
        /// Whether this byte array has an error message.
        /// </summary>
        public Boolean HasErrors       { get; }

        /// <summary>
        /// Whether this byte array has no error message.
        /// </summary>
        public Boolean HasNoErrors
            => !HasErrors;

        /// <summary>
        /// The length of the byte array.
        /// </summary>
        public UInt64  Length
            => (UInt64) Data.Length;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new byte array with an optional error message.
        /// </summary>
        /// <param name="Data">A byte array.</param>
        /// <param name="ErrorMessage">An optional error message.</param>
        private ByteArray(Byte[]  Data,
                          String  ErrorMessage)
        {

            this.Data          = Data;
            this.ErrorMessage  = ErrorMessage;

            this.HasErrors     = Data.        Length == 0 ||
                                 ErrorMessage.Length  > 0;

        }

        #endregion


        #region (static) Ok       (Data)

        /// <summary>
        /// Create a new byte array.
        /// </summary>
        /// <param name="Data">A byte array.</param>
        public static ByteArray Ok(Byte[] Data)

            => new (Data,
                    String.Empty);

        #endregion

        #region (static) Error    (ErrorMessage)

        /// <summary>
        /// Create a new byte array having the given error message.
        /// </summary>
        /// <param name="ErrorMessage">An error message.</param>
        public static ByteArray Error(String ErrorMessage)

            => new (Array.Empty<Byte>(),
                    ErrorMessage);

        #endregion

        #region (static) Exception(ErrorMessage)

        /// <summary>
        /// Create a new byte array having the given exception.
        /// </summary>
        /// <param name="Exception">An exception.</param>
        public static ByteArray Exception(Exception Exception)

            => new (Array.Empty<Byte>(),
                    Exception.Message);

        #endregion


        #region (implicit, operator) ToByte[]

        /// <summary>
        /// Implicitly convert this ByteArray to a standard byte array.
        /// </summary>
        /// <param name="ByteArray">A ByteArray.</param>
        public static implicit operator Byte[] (ByteArray ByteArray)

            => ByteArray.Data;

        #endregion


        #region Operator overloading

        #region Operator == (ByteArray1, ByteArray2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ByteArray1">A byte array.</param>
        /// <param name="ByteArray2">Another byte array.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (ByteArray ByteArray1,
                                           ByteArray ByteArray2)

            => ByteArray1.Equals(ByteArray2);

        #endregion

        #region Operator != (ByteArray1, ByteArray2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ByteArray1">A byte array.</param>
        /// <param name="ByteArray2">Another byte array.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (ByteArray ByteArray1,
                                           ByteArray ByteArray2)

            => !ByteArray1.Equals(ByteArray2);

        #endregion

        #region Operator <  (ByteArray1, ByteArray2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ByteArray1">A byte array.</param>
        /// <param name="ByteArray2">Another byte array.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (ByteArray ByteArray1,
                                          ByteArray ByteArray2)

            => ByteArray1.CompareTo(ByteArray2) < 0;

        #endregion

        #region Operator <= (ByteArray1, ByteArray2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ByteArray1">A byte array.</param>
        /// <param name="ByteArray2">Another byte array.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (ByteArray ByteArray1,
                                           ByteArray ByteArray2)

            => ByteArray1.CompareTo(ByteArray2) <= 0;

        #endregion

        #region Operator >  (ByteArray1, ByteArray2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ByteArray1">A byte array.</param>
        /// <param name="ByteArray2">Another byte array.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (ByteArray ByteArray1,
                                          ByteArray ByteArray2)

            => ByteArray1.CompareTo(ByteArray2) > 0;

        #endregion

        #region Operator >= (ByteArray1, ByteArray2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ByteArray1">A byte array.</param>
        /// <param name="ByteArray2">Another byte array.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (ByteArray ByteArray1,
                                           ByteArray ByteArray2)

            => ByteArray1.CompareTo(ByteArray2) >= 0;

        #endregion

        #endregion

        #region IComparable<ByteArray> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two byte arrays.
        /// </summary>
        /// <param name="Object">A byte array to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is ByteArray byteArray
                   ? CompareTo(byteArray)
                   : throw new ArgumentException("The given object is not a byte array!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(ByteArray)

        /// <summary>
        /// Compares two byte arrays.
        /// </summary>
        /// <param name="ByteArray">A byte array to compare with.</param>
        public Int32 CompareTo(ByteArray ByteArray)
        {

            var c = Data.Length.CompareTo(ByteArray.Data.Length);

            if (c == 0)
            {
                for (var i = 0U; i < Data.Length; i++)
                {

                    c = Data[i].CompareTo(ByteArray.Data[i]);

                    if (c != 0)
                        break;

                }
            }

            if (c == 0)
                c = String.Compare(ErrorMessage,
                                   ByteArray.ErrorMessage,
                                   StringComparison.Ordinal);

            return c;

        }

        #endregion

        #endregion

        #region IEquatable<ByteArray> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two byte arrays for equality.
        /// </summary>
        /// <param name="Object">A byte array to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is ByteArray byteArray &&
                   Equals(byteArray);

        #endregion

        #region Equals(ByteArray)

        /// <summary>
        /// Compares two byte arrays for equality.
        /// </summary>
        /// <param name="ByteArray">A byte array to compare with.</param>
        public Boolean Equals(ByteArray ByteArray)
        {

            if (Data.Length != ByteArray.Data.Length)
                return false;

            for (var i = 0U; i < Data.Length; i++)
            {

                if (Data[i] != ByteArray.Data[i])
                    return false;

            }

            return String.Equals(ErrorMessage,
                                 ByteArray.ErrorMessage,
                                 StringComparison.Ordinal);

        }

        #endregion

        #endregion

        #region GetHashCode()

        /// <summary>
        /// Get the hashcode of this object.
        /// </summary>
        public override Int32 GetHashCode()
        {
            unchecked
            {
                return Data.        GetHashCode() * 3 ^
                       ErrorMessage.GetHashCode();
            }
        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"{Data.Length} bytes, {(HasErrors ? $"error message: {ErrorMessage}" : "no error(s)")}";

        #endregion

    }

}
