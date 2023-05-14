
#region Usings

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// This is the core implementation of IIP.
    /// </summary>
    public class SymmetricEncryptionWithIntegrityPadding
    {

        #region Data

        private static readonly String[]                     CHAINING_WITHOUT_DIFFUSION = { "CFB", "OFB", "CTR", "GCM" };
        private        readonly SecureRandom                 rng;
        private        readonly Cipher                       cipher;
        private        readonly Int32                        cipherBlockSize;
        private        readonly InterleavedIntegrityPadding  integrityPaddingInstance;

        #endregion

        #region Properties

        public String Algorithm
            => cipher.AlgorithmName;

        public Byte[] IV
            => cipher.IV;

        #endregion


        #region Constructor(s)

        /// <summary>
        /// Create a new SymmetricEncryptionWithIntegrityPadding.
        /// </summary>
        /// <param name="Cipher">The cipher to use.</param>
        public SymmetricEncryptionWithIntegrityPadding(Cipher Cipher)
        {

            // safety check for "bad" chaining. will not catch all bad ones, but the most common-
            var cipherSpec = Cipher.AlgorithmName;

            if (CHAINING_WITHOUT_DIFFUSION.Contains(cipherSpec))
                throw new Exception("NEVER use streaming ciphers which just XOR their stream in combination with this padding!");

            var blockSize  = Cipher.BlockSize;

            // later implementations may lift this restriction. It is "just" about making sure every block gets a nonce.
            if (blockSize != 16)
                throw new Exception("this implementation is optimised for blocksize 16");

            // current implementation is tuned for an extra block at start
            this.cipherBlockSize           = Cipher.BlockSize;
            this.cipher                    = Cipher;
            this.integrityPaddingInstance  = new InterleavedIntegrityPadding(cipherBlockSize);
            this.rng                       = new SecureRandom();

            //@IMPROVEMENT dynamic IV size, according to cipher?

        }

        #endregion


        #region EncryptOnly  (Cleartext, SecretKey)

        /// <summary>
        /// Encrypt only.
        /// </summary>
        /// <param name="Cleartext">A cleartext.</param>
        /// <param name="SecretKey">A crypto key.</param>
        public Byte[] EncryptOnly(Byte[]        Cleartext,
                                  KeyParameter  SecretKey)
        {

            cipher.Init(CipherMode.ENCRYPT_MODE,
                        SecretKey,
                        rng); // will create its own iv, and we have to retrieve it later with cipher.getIV();

            return cipher.DoFinal(Cleartext);

        }

        #endregion

        #region PadAndEncrypt(Cleartext, SecretKey)

        /// <summary>
        /// 
        /// </summary>
        /// <param name="Cleartext">A cleartext.</param>
        /// <param name="SecretKey">A crypto key.</param>
        public Byte[] PadAndEncrypt(Byte[]        Cleartext,
                                    KeyParameter  SecretKey)

            => EncryptOnly(integrityPaddingInstance.PerformPaddingWithAllocation(Cleartext),
                           SecretKey);

        #endregion


        #region DecryptAndCheck(Ciphertext, SecretKey, InitializationVector = null)

        /// <summary>
        /// Decrypt and check.
        /// </summary>
        /// <param name="Ciphertext">A ciphertext.</param>
        /// <param name="SecretKey">A crypto key.</param>
        /// <param name="InitializationVector">An optional cryptographic initialization vector.</param>
        public Byte[] DecryptAndCheck(Byte[]        Ciphertext,
                                      KeyParameter  SecretKey,
                                      Byte[]?       InitializationVector   = null)
        {

            if (InitializationVector is not null && InitializationVector.Length > 0)
                cipher.Init(CipherMode.DECRYPT_MODE,
                            SecretKey,
                            new IvParameterSpec(InitializationVector)); // Will create its own iv, and we have to retrieve it later with cipher.getIV();

            else
                cipher.Init(CipherMode.DECRYPT_MODE,
                            SecretKey);

            var decryptedData = cipher.DoFinal(Ciphertext);

            return integrityPaddingInstance.CheckAndExtract(decryptedData);

        }

        #endregion


    }

}
