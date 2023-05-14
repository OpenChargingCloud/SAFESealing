
#region Usings

using Org.BouncyCastle.Asn1;

#endregion

namespace SAFESealing
{

    public class CryptoSettings
    {

        #region Properties

        public AlgorithmSpec?        Encryption                     { get; }
        public AlgorithmSpec?        Padding                        { get; }
        public AlgorithmSpec?        Compression                    { get; }
        public AlgorithmSpec?        KeyAgreementProtocol           { get; }
        public AlgorithmSpec?        KeyAgreementCipher             { get; }
        public AlgorithmSpec?        KeyDiversificationAlgorithm    { get; }
        public UInt32?               EncryptionKeySize              { get; }

        public DerObjectIdentifier?  CompressionOID
            => Compression?.OID;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create new crypto settings.
        /// </summary>
        /// <param name="KeyAgreementProtocolToUse">Key Agreement protocol. currently supported: null, ECDH</param>
        /// <param name="KeyAgreementCipherToUse">cipher to use in key agreemnet. currently supported: some EC curves  @TODO list/reference</param>
        /// <param name="KeyDiversificationToUse">key diversification algorithm. currently supported: SHA-256, SHA-512</param>
        /// <param name="EncryptionToUse">encryption to use. with key agreement, this should be symmetric (AES-256); without, this should be asymmetric (RSA-2048).</param>
        /// <param name="CompressionUsed">indicator for recipient whether sender used some compression on the content. Implementation just passes this on, it is not performed here.</param>
        /// <param name="PaddingToUse"></param>
        /// <param name="EncryptionKeySize"></param>
        public CryptoSettings(AlgorithmSpec?  KeyAgreementProtocolToUse,
                              AlgorithmSpec?  KeyAgreementCipherToUse,
                              AlgorithmSpec?  KeyDiversificationToUse,
                              AlgorithmSpec   EncryptionToUse,
                              AlgorithmSpec   CompressionUsed,
                              AlgorithmSpec?  PaddingToUse,
                              UInt32?         EncryptionKeySize)
        {

            this.Compression                  = CompressionUsed;
            this.Padding                      = PaddingToUse ?? AlgorithmSpecCollection.IIP;
            this.Encryption                   = EncryptionToUse;
            this.KeyDiversificationAlgorithm  = KeyDiversificationToUse;
            this.KeyAgreementCipher           = KeyAgreementCipherToUse;
            this.KeyAgreementProtocol         = KeyAgreementProtocolToUse;
            this.EncryptionKeySize            = EncryptionKeySize;

            if (Padding != AlgorithmSpecCollection.IIP)
                throw new Exception("Only supported padding variant by now!");

            // We could check encryption some more;
            // But since our lookup will work only for algorithms specified here anyways.
            if (KeyAgreementProtocol is not null) // if in use at all
            {

                if (KeyAgreementProtocol != AlgorithmSpecCollection.ECDH)
                    throw new Exception("Only supported key agreement protocol by now!");

                if (KeyDiversificationAlgorithm is null)
                    throw new Exception("if keyAgreement, then a key diversification algorithm is required!");
                    // currently optional; the provided key will determine the curve. if (keyAgreementCipher == null) return false; -- improvement.

            }

        }

        #endregion


        #region Static lookups...

        public static AlgorithmSpec? GetEncryptionOID(DerObjectIdentifier oid)
            => LookupValidatedByOID(oid, AlgorithmSpec.CryptoTypes.CIPHER);

        public static AlgorithmSpec? GetPaddingOID(DerObjectIdentifier oid)
            => LookupValidatedByOID(oid, AlgorithmSpec.CryptoTypes.PADDING);

        public static AlgorithmSpec? GetCompressionOID(DerObjectIdentifier oid)
            => LookupValidatedByOID(oid, AlgorithmSpec.CryptoTypes.COMPRESSION);

        public static AlgorithmSpec? GetKeyAgreementProtocolByOID(DerObjectIdentifier oid)
            => LookupValidatedByOID(oid, AlgorithmSpec.CryptoTypes.KEY_AGREEMENT);

        public static AlgorithmSpec? GetKeyAgreementCipherOID(DerObjectIdentifier oid)
            => LookupValidatedByOID(oid, AlgorithmSpec.CryptoTypes.ELLIPTIC_CURVE);

        public static AlgorithmSpec? GetKeyDiversificationOID(DerObjectIdentifier oid)
            => LookupValidatedByOID(oid, AlgorithmSpec.CryptoTypes.DIGEST);


        private static AlgorithmSpec? LookupValidatedByOID(DerObjectIdentifier        OID,
                                                           AlgorithmSpec.CryptoTypes  ExpectedType)
        {

            // null is valid for not used/not set.
            if (OID is null)
                return null;

            var spec = AlgorithmSpecCollection.LookupByOID(OID) ?? throw new Exception("algorithm not supported in current implementation: " + OID.Id);

            if (spec.CryptoType != ExpectedType)
                throw new Exception($"Algorithm used in wrong function '{OID.Id}'!");

            return spec;

        }

        #endregion


    }

}
