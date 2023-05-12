using Org.BouncyCastle.Asn1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace SAFESealing
{
    public class CryptoSettingsStruct
    {

        public AlgorithmSpec?  Encryption                       { get; set; }
        public AlgorithmSpec?  Padding                          { get; set; }
        public AlgorithmSpec?  Compression                      { get; set; }
        public AlgorithmSpec?  KeyAgreementProtocol             { get; set; }
        public AlgorithmSpec?  KeyAgreementCipher               { get; set; }
        public AlgorithmSpec?  KeyDiversificationAlgorithm      { get; set; }
        public UInt32          EncryptionKeySize                { get; set; }


        public void SetEncryptionOID(DerObjectIdentifier oid)
        {
            this.Encryption                   = LookupValidatedByOID(oid, AlgorithmSpec.CryptoTypes.CIPHER);
        }

        public void SetPaddingOID(DerObjectIdentifier oid)
        {
            this.Padding                      = LookupValidatedByOID(oid, AlgorithmSpec.CryptoTypes.PADDING);
        }

        public void SetCompressionOID(DerObjectIdentifier oid)
        {
            this.Compression                  = LookupValidatedByOID(oid, AlgorithmSpec.CryptoTypes.COMPRESSION);
        }

        public void SetKeyAgreementProtocolByOID(DerObjectIdentifier oid)
        {
            this.KeyAgreementProtocol         = LookupValidatedByOID(oid, AlgorithmSpec.CryptoTypes.KEY_AGREEMENT);
        }

        public void SetKeyAgreementCipherOID(DerObjectIdentifier oid)
        {
            this.KeyAgreementCipher           = LookupValidatedByOID(oid, AlgorithmSpec.CryptoTypes.ELLIPTIC_CURVE);
        }

        public void SetKeyDiversificationOID(DerObjectIdentifier oid)
        {
            this.KeyDiversificationAlgorithm  = LookupValidatedByOID(oid, AlgorithmSpec.CryptoTypes.DIGEST);
        }


    /// <summary>
    /// Constructor for the defined use cases, initialising with default values.
    /// </summary>
    /// <param name="WithKeyAgreement">When false: RSA 2048 with IIP; RSA/ECB/NoPadding+IIP at 2048 bit, else: ECDHE with secp256r1 and AES/CBC 256 bit.</param>
    public CryptoSettingsStruct(Boolean WithKeyAgreement)
        {

            if (WithKeyAgreement) {
                this.Compression                  = AlgorithmSpecCollection.COMPRESSION_NONE;
                this.Padding                      = AlgorithmSpecCollection.IIP;
                this.Encryption                   = AlgorithmSpecCollection.AES256CBC;
                // for deriving the symmetric ephemeral key, we need this for ECHDE
                this.KeyAgreementProtocol         = AlgorithmSpecCollection.ECDH;
                this.KeyAgreementCipher           = AlgorithmSpecCollection.ECSECP256R1;
                this.KeyDiversificationAlgorithm  = AlgorithmSpecCollection.SHA256;
                this.EncryptionKeySize            = Encryption.KeySizeInBit;
            }
            else {
                this.Compression                  = AlgorithmSpecCollection.COMPRESSION_NONE;
                this.Padding                      = AlgorithmSpecCollection.IIP;
                this.Encryption                   = AlgorithmSpecCollection.RSA2048;
                this.EncryptionKeySize            = Encryption.KeySizeInBit;
                this.KeyAgreementProtocol         = null;
                this.KeyAgreementCipher           = null;
                this.KeyDiversificationAlgorithm  = null;
            }

        }

        /// <summary>
        /// Fully parameterised constructor.
        /// </summary>
        /// <param name="keyAgreementProtocolToUse">Key Agreement protocol. currently supported: null, ECDH</param>
        /// <param name="keyAgreementCipherToUse">cipher to use in key agreemnet. currently supported: some EC curves  @TODO list/reference</param>
        /// <param name="keyDiversificationToUse">key diversification algorithm. currently supported: SHA-256, SHA-512</param>
        /// <param name="encryptionToUse">encryption to use. with key agreement, this should be symmetric (AES-256); without, this should be asymmetric (RSA-2048).</param>
        /// <param name="compressionUsed">indicator for recipient whether sender used some compression on the content. Implementation just passes this on, it is not performed here.</param>
        public CryptoSettingsStruct(AlgorithmSpec? keyAgreementProtocolToUse,
                                    AlgorithmSpec? keyAgreementCipherToUse,
                                    AlgorithmSpec? keyDiversificationToUse,
                                    AlgorithmSpec  encryptionToUse,
                                    AlgorithmSpec  compressionUsed)
        {

            this.Compression                  = compressionUsed;
            this.Padding                      = AlgorithmSpecCollection.IIP;
            this.Encryption                   = encryptionToUse;
            this.KeyDiversificationAlgorithm  = keyDiversificationToUse;
            this.KeyAgreementCipher           = keyAgreementCipherToUse;
            this.KeyAgreementProtocol         = keyAgreementProtocolToUse;

        }



        public DerObjectIdentifier? CompressionOID
            => Compression?.OID;


        private AlgorithmSpec? LookupValidatedByOID(DerObjectIdentifier        oid,
                                                    AlgorithmSpec.CryptoTypes  expectedType)
        {

            // null is valid for not used/not set.
            if (oid is null)
                return null;

            var spec = AlgorithmSpecCollection.LookupByOID(oid) ?? throw new Exception("algorithm not supported in current implementation: " + oid.Id);

            if (spec.CryptoType != expectedType)
                throw new Exception("algorithm used in wrong function: " + oid.Id);

            return spec;

        }

        /**
         * <p>validate.</p>
         *
         * @return a boolean
         */
        public Boolean validate()
        {

            if (Padding != AlgorithmSpecCollection.IIP)
                return false; // only supported variant now.

            if (Encryption is null)
                return false; // required.

            // we could check encryption some more; but since our lookup will work only for algorithms specified here anyways.
            if (KeyAgreementProtocol is not null) // if in use at all
            {

                if (KeyAgreementProtocol != AlgorithmSpecCollection.ECDH)
                    return false; // only supported variant now

                if (KeyDiversificationAlgorithm is null)
                    return false; // if keyAgreement, then this is required
                                  // currently optional; the provided key will determine the curve. if (keyAgreementCipher == null) return false; -- improvement.

            }

            return true;

        }



    }

}
