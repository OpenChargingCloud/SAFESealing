
#region Usings

using System.Security.Cryptography;

using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// Performs Interleaved Integrity Padding using AES and Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) for shared keys.
    /// </summary>
    public class ECDHEWithIntegrityPadding
    {

        #region Data

        private readonly AlgorithmSpec                            algorithmSpec;
        private readonly ECDHBasicAgreement                       keyAgreement;
        private readonly SymmetricEncryptionWithIntegrityPadding  symmetricEncryption;

        #endregion

        #region Properties

        /// <summary>
        /// Return the symmetric IV.
        /// </summary>
        public Byte[] SymmetricIV
            => symmetricEncryption.IV;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new Interleaved Integrity Padding using AES and Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) for shared keys.
        /// </summary>
        /// <param name="AlgorithmSpec">The (symmetric) encryption algorithm to be used</param>
        public ECDHEWithIntegrityPadding(AlgorithmSpec  AlgorithmSpec)
        {

            this.algorithmSpec        = AlgorithmSpec;
            this.keyAgreement         = new ECDHBasicAgreement();
            this.symmetricEncryption  = //new SymmetricEncryptionWithIntegrityPadding(
                                        //    CryptoFactory.GetCipherFromCipherSpec(this.algorithmSpec)
                                        //        ?? throw new ArgumentNullException(nameof(AlgorithmSpec), "Invalid (symmetric) encryption algorithm!")
                                        //);
                                        SymmetricEncryptionWithIntegrityPadding.AES_ECB_NoPKCS7;

        }

        #endregion


        #region (private) CreateEphemeralAESKey(OtherSideECPublicKey,  OurECPrivateKey, Nonce)

        /// <summary>
        /// Create a ephemeral symmetric key for AES encryption (shared secret)
        /// from one party's private key and another party's public key
        /// using on Elliptic Curve Diffie-Hellman (ECDH).
        /// </summary>
        /// <param name="OtherSideECPublicKey">An elliptic curve public key.</param>
        /// <param name="OurECPrivateKey">An elliptic curve private key.</param>
        /// <param name="Nonce">A cryptographic nonce for increasing the entropy.</param>
        private KeyParameter CreateEphemeralAESKey(ECPublicKeyParameters   OtherSideECPublicKey,
                                                   ECPrivateKeyParameters  OurECPrivateKey,
                                                   Byte[]                  Nonce)
        {

            keyAgreement.Init(OurECPrivateKey);

            // This is where we use SHA256 for key derivation.
            // SHA-512 would produce 64 byte keys instead.
            // It is *not* related to the input data in any way!
            var kdf     = SHA256.Create();
            var secret  = keyAgreement.CalculateAgreement(OtherSideECPublicKey).ToByteArray();
            kdf.TransformBlock     (Nonce,  0, Nonce. Length, null, 0);
            kdf.TransformFinalBlock(secret, 0, secret.Length);

            return new KeyParameter(kdf.Hash);

        }

        #endregion

        #region (private) CreateEphemeralAESKey(OtherSideECPublicKeys, OurECPrivateKey, Nonce)

        /// <summary>
        /// Create the ephemeral symmetric key, for AES, for multiple recipients.
        /// </summary>
        /// <param name="OtherSideECPublicKeys">An enumeration of elliptic curve public keys.</param>
        /// <param name="OurECPrivateKey">An elliptic curve private key.</param>
        /// <param name="Nonce">A cryptographic nonce for increasing the entropy.</param>
        private KeyParameter CreateEphemeralAESKey(IEnumerable<ECPublicKeyParameters>  OtherSideECPublicKeys,
                                                   ECPrivateKeyParameters              OurECPrivateKey,
                                                   Byte[]                              Nonce)
        {

            keyAgreement.Init(OurECPrivateKey);

            //foreach (var publicKey in MultipleRecipientKeys)
            //    keyAgreement.doPhase(publicKey, true); // multi-recipient DH.

            // this is where we use SHA, for key derivation. It is *not* related to the input data in any way!
            //@TODO delegate to CryptoFactory
            var kdf     = SHA256.Create();  // SHA-512 would produce 64 byte keys instead.
            var secret  = keyAgreement.CalculateAgreement(OtherSideECPublicKeys.First()).ToByteArray();
            kdf.TransformBlock     (Nonce,  0, Nonce. Length, null, 0);
            kdf.TransformFinalBlock(secret, 0, secret.Length);

            return new KeyParameter(kdf.Hash);

            //@TODO improvement variable size of AES key
            // kdf.digest(); will provide now 64 bytes since it is SHA-512. AES can take only 16, 24, 32 byte for 128, 192, 256 bit keys.
            // we would need to cut "n"byte out of the hash result here depending on the AES size specified.
            //var secretKeySpec  = new SecretKeySpec(kdf.digest(), "AES"); // prepare the key input
            //var ephKey         = SecretKeyFactory.getInstance("AES").generateSecret(secretKeySpec); // and turn it into an AES key
            //
            //return ephKey;

        }

        #endregion


        #region PadEncryptAndPackage(Plaintext, OtherSideECPublicKey,  OurECPrivateKey, Nonce)

        /// <summary>
        /// Pad encrypt and package.
        /// </summary>
        /// <param name="Plaintext">A plaintext.</param>
        /// <param name="OtherSideECPublicKey">An elliptic curve public key.</param>
        /// <param name="OurECPrivateKey">An elliptic curve private key.</param>
        /// <param name="Nonce">A cryptographic nonce for increasing the entropy.</param>
        public Byte[] PadEncryptAndPackage(Byte[]                  Plaintext,
                                           ECPublicKeyParameters   OtherSideECPublicKey,
                                           ECPrivateKeyParameters  OurECPrivateKey,
                                           Byte[]                  Nonce)


            => symmetricEncryption.PadAndEncrypt(Plaintext,
                                                 CreateEphemeralAESKey(OtherSideECPublicKey,
                                                                       OurECPrivateKey,
                                                                       Nonce));

        #endregion

        #region PadEncryptAndPackage(Plaintext, OtherSideECPublicKeys, OurECPrivateKey, Nonce)

        /// <summary>
        /// Pad encrypt and package for multiple recipients.
        /// </summary>
        /// <param name="Plaintext">an array of {@link byte} objects</param>
        /// <param name="OtherSideECPublicKeys">An enumeration of elliptic curve public keys.</param>
        /// <param name="OurECPrivateKey">An elliptic curve private key.</param>
        /// <param name="Nonce">A cryptographic nonce for increasing the entropy.</param>
        public Byte[] PadEncryptAndPackage(Byte[]                              Plaintext,
                                           IEnumerable<ECPublicKeyParameters>  OtherSideECPublicKeys,
                                           ECPrivateKeyParameters              OurECPrivateKey,
                                           Byte[]                              Nonce)


            => symmetricEncryption.PadAndEncrypt(Plaintext,
                                                 CreateEphemeralAESKey(OtherSideECPublicKeys,
                                                                       OurECPrivateKey,
                                                                       Nonce));

        #endregion


        #region DecryptAndVerify(Ciphertext, OtherSideECPublicKey, OurECPrivateKey, Nonce, IVForSymmetricCrypto)

        /// <summary>
        /// Decrypt and verify.
        /// </summary>
        /// <param name="Ciphertext">A ciphertext.</param>
        /// <param name="OtherSideECPublicKey">An elliptic curve public key.</param>
        /// <param name="OurECPrivateKey">An elliptic curve private key.</param>
        /// <param name="Nonce">A cryptographic nonce for increasing the entropy.</param>
        /// <param name="InitializationVector">A cryptographic initialization vector.</param>
        public Byte[] DecryptAndVerify(Byte[]                  Ciphertext,
                                       ECPublicKeyParameters   OtherSideECPublicKey,
                                       ECPrivateKeyParameters  OurECPrivateKey,
                                       Byte[]                  Nonce,
                                       Byte[]                  InitializationVector)


            => symmetricEncryption.DecryptAndCheck(Ciphertext,
                                                   CreateEphemeralAESKey(OtherSideECPublicKey,
                                                                         OurECPrivateKey,
                                                                         Nonce),
                                                   InitializationVector);

        #endregion


    }

}
