using Org.BouncyCastle.Crypto;

#region Usings

using System.Security.Cryptography;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// Performs IIP with symmetric keys derived from an ECDHE procedure.
    /// </summary>
    public class ECDHEWithIntegrityPadding : IAsymmetricEncryptionWithIIP
    {

        private readonly ICryptoFactory                           cryptoFactory;
        private readonly AlgorithmSpec                            algorithmSpec;
        private readonly SecureRandom                             rng;
        private readonly ECDHBasicAgreement                       keyAgreement;
        private readonly SymmetricEncryptionWithIntegrityPadding  symmetricEncryption;



        /// <summary>
        /// Return the symmetric IV.
        /// </summary>
        public Byte[] SymmetricIV
            => symmetricEncryption.IV;


        /**
         * default constructor
         *
         * @throws java.security.NoSuchAlgorithmException if any.
         * @throws java.security.NoSuchProviderException if any.
         * @throws javax.crypto.NoSuchPaddingException if any.
         * @throws java.security.InvalidKeyException if any.
         */
        /*
            public ECDHEWithIntegrityPadding()
                    throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException
                {
                if (Security.getProvider("BC") == null)
                    Security.addProvider(new BouncyCastleProvider());
                init(Security.getProvider("BC"));
                }
            */


        /// <summary>
        /// Constructor for Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) IIP
        /// </summary>
        /// <param name="AlgorithmSpec">(symmetric) encryption algorithm to be used</param>
        public ECDHEWithIntegrityPadding(ICryptoFactory  CryptoFactory,
                                         AlgorithmSpec   AlgorithmSpec)
        {

            this.cryptoFactory        = CryptoFactory;
            this.algorithmSpec        = AlgorithmSpec;
            this.rng                  = new SecureRandom();
            this.keyAgreement         = new ECDHBasicAgreement();

            // Cipher symmetricCipher = Cipher.getInstance("AES/ECB/NoPadding"); // default cipher
            var symmetricCipher       = CryptoFactory.GetCipherFromCipherSpec(this.algorithmSpec);
            this.symmetricEncryption  = new SymmetricEncryptionWithIntegrityPadding(symmetricCipher, this.cryptoFactory); // default cipher spec

        }


        #region CreateEphemeralAESKey(OtherSideECPublicKey, OurECPrivateKey, Nonce)

        /// <summary>
        /// Create a ephemeral symmetric key for AES encryption (shared secret)
        /// from one party's private key and another party's public key
        /// using on Elliptic Curve Diffie-Hellman (ECDH).
        /// </summary>
        /// <param name="OtherSideECPublicKey">An elliptic curve public key.</param>
        /// <param name="OurECPrivateKey">An elliptic curve private key.</param>
        /// <param name="Nonce">A nonce for increasing the entropy.</param>
        /// <returns>ephemeral secret key</returns>
        KeyParameter CreateEphemeralAESKey(ECPublicKeyParameters   OtherSideECPublicKey,
                                           ECPrivateKeyParameters  OurECPrivateKey,
                                           Byte[]                  Nonce)
        {

            keyAgreement.Init(OurECPrivateKey);

            // This is where we use SHA256 for key derivation.
            // SHA-512 would produce 64 byte keys instead.
            // It is *not* related to the input data in any way!
            var kdf     = SHA256.Create();
            var secret  = keyAgreement.CalculateAgreement(OtherSideECPublicKey).ToByteArray();
            kdf.TransformBlock     (Nonce, 0, Nonce.Length, null, 0);
            kdf.TransformFinalBlock(secret,   0, secret.  Length);

            return new KeyParameter(kdf.Hash);

        }

        #endregion



        /// <summary>
        /// Create the ephemeral symmetric key, for AES, for multiple recipients.
        /// </summary>
        /// <param name="MultipleRecipientKeys"></param>
        /// <param name="OurECPrivateKey"></param>
        /// <param name="Nonce"></param>
        /// <returns></returns>
        KeyParameter CreateEphemeralAESKey(IEnumerable<ECPublicKeyParameters>  MultipleRecipientKeys,
                                           ECPrivateKeyParameters              OurECPrivateKey,
                                           Byte[]                              Nonce)
        {

            keyAgreement.Init(OurECPrivateKey);

            //foreach (var publicKey in MultipleRecipientKeys)
            //    keyAgreement.doPhase(publicKey, true); // multi-recipient DH.

            // this is where we use SHA, for key derivation. It is *not* related to the input data in any way!
            //@TODO delegate to CryptoFactory
            var kdf     = SHA256.Create();  // SHA-512 would produce 64 byte keys instead.
            var secret  = keyAgreement.CalculateAgreement(MultipleRecipientKeys.First()).ToByteArray();
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


        /// <summary>
        /// Pad encrypt and package.
        /// </summary>
        /// <param name="Data">An array of {@link byte} objects</param>
        /// <param name="OtherSideECPublicKey">a {@link java.security.PublicKey} object</param>
        /// <param name="OurECPrivateKey">a {@link java.security.PrivateKey} object</param>
        /// <param name="KeyDiversification">an array of {@link byte} objects</param>
        /// <returns>an array of {@link byte} objects</returns>
        public Byte[] PadEncryptAndPackage(Byte[]                  Data,
                                           ECPublicKeyParameters   OtherSideECPublicKey,
                                           ECPrivateKeyParameters  OurECPrivateKey,
                                           Byte[]                  KeyDiversification)
        {

            // derive symmetric ephemeral key
            var ephemeralKey = CreateEphemeralAESKey(OtherSideECPublicKey,
                                                     OurECPrivateKey,
                                                     KeyDiversification);

            // pad+encrypt content
            var rawEncrypted = symmetricEncryption.PadAndEncrypt(Data, ephemeralKey);

            return rawEncrypted;

        }


        /// <summary>
        /// Pad encrypt and package for multiple recipients.
        /// </summary>
        /// <param name="ContentToSeal">an array of {@link byte} objects</param>
        /// <param name="RecipientKeys">an array of {@link java.security.PublicKey} objects</param>
        /// <param name="SenderKey">a {@link java.security.PrivateKey} object</param>
        /// <param name="KseyDiversificationForEC">an array of {@link byte} objects</param>
        /// <returns>an array of {@link byte} objects</returns>
        public Byte[] PadEncryptAndPackage(Byte[]                              ContentToSeal,
                                           IEnumerable<ECPublicKeyParameters>  RecipientKeys,
                                           ECPrivateKeyParameters              SenderKey,
                                           Byte[]                              KeyDiversificationForEC)
        {

            var ephemeralKey = CreateEphemeralAESKey(RecipientKeys,
                                                     SenderKey,
                                                     KeyDiversificationForEC);

            // pad+encrypt content
            var rawEncrypted = symmetricEncryption.PadAndEncrypt(ContentToSeal, ephemeralKey);

            // clear ephemeral key from memory where applicable
            // ephemeralKey.destroy();
            return rawEncrypted;

        }


        /// <summary>
        /// Decrypt and verify.
        /// </summary>
        /// <param name="EncryptedData">an array of {@link byte} objects</param>
        /// <param name="OtherSideECPublicKey">a {@link java.security.PublicKey} object</param>
        /// <param name="OurECPrivateKey">a {@link java.security.PrivateKey} object</param>
        /// <param name="KeyDiversificationForEC">an array of {@link byte} objects</param>
        /// <param name="IVForSymmetricCrypto">an array of {@link byte} objects</param>
        /// <returns>an array of {@link byte} objects</returns>
        public Byte[] DecryptAndVerify(Byte[]                  EncryptedData,
                                       ECPublicKeyParameters   OtherSideECPublicKey,
                                       ECPrivateKeyParameters  OurECPrivateKey,
                                       Byte[]                  KeyDiversificationForEC,
                                       Byte[]                  IVForSymmetricCrypto)
        {

            // derive symmetric ephemeral key
            var ephemeralKey = CreateEphemeralAESKey(OtherSideECPublicKey,
                                                     OurECPrivateKey,
                                                     KeyDiversificationForEC);

            // perform symmetric decryption and padding integrity checks.
            var decrypted = symmetricEncryption.DecryptAndCheck(EncryptedData,
                                                                ephemeralKey,
                                                                IVForSymmetricCrypto);

            // not replacing the data in ids here since there's nothing to protect
            return decrypted;

        }


    }

}
