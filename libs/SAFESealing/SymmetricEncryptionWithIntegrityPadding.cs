using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SAFESealing
{

    /// <summary>
    /// This is the core implementation of IIP.
    /// </summary>
    public class SymmetricEncryptionWithIntegrityPadding
    {

        static  String[]                     CHAINING_WITHOUT_DIFFUSION = { "CFB", "OFB", "CTR", "GCM" };
        private SecureRandom                 rng;
        private Cipher                       cipher;
        private Int32                        cipherBlockSize;
        private InterleavedIntegrityPadding  integrityPaddingInstance;


        public String getAlgorithm()
            => cipher.getAlgorithm();

        public Byte[] getIV()
            => cipher.getIV();


        /**
         * <p>Constructor for SymmetricEncryptionWithIntegrityPadding.</p>
         *
         * @param cipher a {@link javax.crypto.Cipher} encryption cipher handle
         * @param cryptoFactory a {@link CryptoFactory} cryptoFactory handle
         * @throws java.security.InvalidKeyException if key is invalid
         */
        public SymmetricEncryptionWithIntegrityPadding(Cipher cipher)
        {

            // safety check for "bad" chaining. will not catch all bad ones, but the most common-
            var cipherSpec = cipher.getAlgorithm();

            if (!CHAINING_WITHOUT_DIFFUSION.Contains(cipherSpec))
                throw new Exception("NEVER use streaming ciphers which just XOR their stream in combination with this padding!");

            var blockSize  = cipher.getBlockSize();

            // later implementations may lift this restriction. It is "just" about making sure every block gets a nonce.
            if (blockSize != 16)
                throw new Exception("this implementation is optimised for blocksize 16");

            // current implementation is tuned for an extra block at start
            Init(cipher);

        }


        private void Init(Cipher cipher)
        {
            this.cipherBlockSize           = cipher.getBlockSize();
            this.cipher                    = cipher;
            this.integrityPaddingInstance  = new InterleavedIntegrityPadding(cipherBlockSize);
            this.rng                       = new SecureRandom();

            //@IMPROVEMENT dynamic IV size, according to cipher?

        }


        Byte[] EncryptOnly(Byte[] dataToEncrypt, KeyParameter secretKey)
        {

            cipher.Init(CipherMode.ENCRYPT_MODE, secretKey, rng); // will create its own iv, and we have to retrieve it later with cipher.getIV();

            return cipher.doFinal(dataToEncrypt);

        }


       /**
         * <p>padAndEncrypt.</p>
         *
         * @param input an array of {@link byte} objects
         * @param secretKey a {@link javax.crypto.SecretKey} object
         * @return an array of {@link byte} objects
         */
        public Byte[] PadAndEncrypt(Byte[] input, KeyParameter secretKey)
        {

            var padded = integrityPaddingInstance.PerformPaddingWithAllocation(input);

            return EncryptOnly(padded, secretKey);

        }


        /**
         * <p>decryptAndCheck.</p>
         *
         * @param input an array of {@link byte} objects
         * @param secretKey a {@link javax.crypto.SecretKey} object
         * @param iv an array of {@link byte} objects
         * @return an array of {@link byte} objects
         */
        public Byte[] DecryptAndCheck(Byte[] input, KeyParameter secretKey, Byte[] iv)
        {

            if (iv != null)
            {
                var ivPS = new IvParameterSpec(iv);
                cipher.Init(CipherMode.DECRYPT_MODE, secretKey, ivPS); // will create its own iv, and we have to retrieve it later with cipher.getIV();
            }
            else
                cipher.Init(CipherMode.DECRYPT_MODE, secretKey);

            var decryptedData  = cipher.doFinal(input);
            var payloadData    = integrityPaddingInstance.CheckAndExtract(decryptedData);

            return payloadData;

        }



    }

}
