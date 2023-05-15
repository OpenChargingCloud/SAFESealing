
#region Usings

using Org.BouncyCastle.Asn1;

#endregion

namespace SAFESealing
{

    public class AlgorithmSpec
    {

        #region (enum) CryptoTypes

        /// <summary>
        /// The type of cryptographic object
        /// </summary>
        public enum CryptoTypes
        {

            /// <summary>
            /// Compression algorithms
            /// </summary>
            COMPRESSION,

            /// <summary>
            /// Encryption/decryption ciphers
            /// </summary>
            CIPHER,

            /// <summary>
            /// Message digests.
            /// Used here for key diversification or key derivation purposes only.
            /// </summary>
            DIGEST,

            /// <summary>
            /// Key agreement algorithm
            /// </summary>
            KEY_AGREEMENT,

            /// <summary>
            /// Padding schemes
            /// </summary>
            PADDING,

            /// <summary>
            /// Elliptic Curve Cryptography (ECC) curves
            /// </summary>
            ELLIPTIC_CURVE

        }

        #endregion


        #region Properties

        /// <summary>
        /// Algorithm OID.
        /// </summary>
        public DerObjectIdentifier  OID                   { get; set; }

        /// <summary>
        /// Get name (human readable, but for consistency, it should comply with usual specification spelling used e.g. in Cipher lookup.
        /// </summary>
        public String               Name                  { get; set; }

        /// <summary>
        /// Check flag: is asymmetric cipher?
        /// </summary>
        public Boolean              IsAsymmetricCipher    { get; set; }

        /// <summary>
        /// Get the general type, see enum in this class
        /// </summary>
        public CryptoTypes          CryptoType            { get; set; }

        /// <summary>
        /// For keys, get key size in bit.
        /// </summary>
        public UInt32               KeySizeInBit          { get; set; }

        /// <summary>
        /// For block ciphers, get block size in bytes. 0 for not applicable, -1 for stream ciphers.
        /// </summary>
        public UInt32               CipherBlockSize       { get; set; }

        /// <summary>
        /// For block ciphers, get number of bytes in block usable for data. -1 for stream ciphers.
        /// </summary>
        public UInt32               UsableBlockSize       { get; set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Construct an algorithm spec, with reduced content.
        /// </summary>
        /// <param name="OID">the OID</param>
        /// <param name="Name">the name</param>
        /// <param name="CryptoType">the type</param>
        public AlgorithmSpec(DerObjectIdentifier  OID,
                             String               Name,
                             CryptoTypes          CryptoType)
        {

            this.OID         = OID;
            this.Name        = Name;
            this.CryptoType  = CryptoType;
            // leaving everything else on default == 0

        }

        /// <summary>
        /// Construct a complete algorithm spec
        /// </summary>
        /// <param name="OID">the OID</param>
        /// <param name="Name">the name</param>
        /// <param name="CryptoType">the type</param>
        /// <param name="AsymmetricFlag">true if asymmetric crypto, false if symmetric or N/A</param>
        /// <param name="KeySize">key size, <b>in bit</b>, if applicable</param>
        /// <param name="CipherBlockSize">cipher block size, <b>in byte</b>, if applicable</param>
        /// <param name="Tara">bytes of the cipher block not usable for payload</param>
        public AlgorithmSpec(DerObjectIdentifier  OID,
                             String               Name,
                             CryptoTypes          CryptoType,
                             Boolean              AsymmetricFlag,
                             UInt32               KeySize,
                             UInt32               CipherBlockSize,
                             UInt32               Tara)
        {

            this.OID                 = OID;
            this.Name                = Name;
            this.CryptoType          = CryptoType;
            this.IsAsymmetricCipher  = AsymmetricFlag;
            this.KeySizeInBit        = KeySize;
            this.CipherBlockSize     = CipherBlockSize;
            this.UsableBlockSize     = CipherBlockSize - Tara;

        }

        #endregion


        #region ToString()

        public override String ToString()

            => CryptoType switch {

                   CryptoTypes.CIPHER
                       => $"{Name} {KeySizeInBit}",

                   CryptoTypes.COMPRESSION   or
                   CryptoTypes.DIGEST        or
                   CryptoTypes.KEY_AGREEMENT or
                   CryptoTypes.PADDING
                       => Name,

                   //CryptoTypes.ELLIPTIC_CURVE ??????????????

                   _
                       => throw new Exception("internal error, invalid type")

               };

        #endregion

    }

}
