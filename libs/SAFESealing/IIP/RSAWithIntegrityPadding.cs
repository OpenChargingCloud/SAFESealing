
#region Usings

using Org.BouncyCastle.Security;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// Performs Interleaved Integrity Padding using RSA/ECB.
    /// 
    /// Caveat: the MSB of an RSA block is unavailable, since it must be set;
    /// some SecurityProvider implementations may chose to block a byte or more.
    /// </summary>
    public class RSAWithIntegrityPadding
    {

        #region Data

        private readonly AlgorithmSpec                algorithmSpec;
        private readonly Cipher                       cipher;
        private readonly InterleavedIntegrityPadding  integrityPaddingInstance;

        #endregion

        #region Properties

        /// <summary>
        /// Return the symmetric IV.
        /// </summary>
        public Byte[] SymmetricIV

            => Array.Empty<Byte>();

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new Interleaved Integrity Padding using RSA/ECB
        /// </summary>
        /// <param name="AlgorithmSpec">The (symmetric) encryption algorithm to be used</param>
        public RSAWithIntegrityPadding(AlgorithmSpec AlgorithmSpec)
        {

            this.algorithmSpec             = AlgorithmSpec;
            this.cipher                    = CryptoFactory.GetCipherFromCipherSpec(algorithmSpec)
                                                 ?? throw new ArgumentNullException(nameof(AlgorithmSpec), "Invalid (symmetric) encryption algorithm!");
            this.integrityPaddingInstance  = new InterleavedIntegrityPadding(algorithmSpec.UsableBlockSize);

        }

        #endregion


        //ToDo(ahzf): RSA IIP does not yet use the correct RSA key data structure!


        #region PadEncryptAndPackage(Cleartext,  OurRSAPrivateKey)

        /// <summary>
        /// Pad encrypt and package.
        /// </summary>
        /// <param name="Cleartext">A cleartext.</param>
        /// <param name="OurRSAPrivateKey">A RSA private key.</param>
        public Byte[] PadEncryptAndPackage(Byte[]         Cleartext,
                                           RSAPrivateKey  OurRSAPrivateKey)
        {

            var rsaBlocksize     = algorithmSpec.CipherBlockSize;
            var usableBlocksize  = algorithmSpec.UsableBlockSize;

            var padded = integrityPaddingInstance.PerformPaddingWithAllocation(Cleartext);
            //assert (padded.length % usable_blocksize == 0); // if not, our padding has a bug

            // encrypt
            cipher.InitRSAPrivateKey(CipherMode.ENCRYPT_MODE, OurRSAPrivateKey, new SecureRandom());
            //assert (rsaPrivKey.getModulus().bitLength() == algorithmSpec.getKeySizeInBit()); // must match expected size

            // rsa will support single blocks only, so we have to split ourselves.
            var inputLength      = padded.Length;
            var outputLength     = inputLength  / usableBlocksize * rsaBlocksize; // scaling from one to the other
            var encrypted        = new Byte[outputLength];
            var numBlocksInput   = outputLength / rsaBlocksize;

            for (var i = 0; i < numBlocksInput; i++)
                cipher.doFinal(padded,
                               i * usableBlocksize,
                               usableBlocksize,
                               encrypted,
                               i * rsaBlocksize); // different blocksizes. Details matter.

            // cleanup as far as possible
            //Arrays.fill(padded, (byte) 0x00);

            return encrypted;

        }

        #endregion

        #region DecryptAndVerify    (Ciphertext, SenderRSAPublicKey)

        /// <summary>
        /// Decrypt and verify.
        /// </summary>
        /// <param name="Ciphertext">A ciphertext.</param>
        /// <param name="SenderRSAPublicKey">A RSA public key.</param>
        public Byte[] DecryptAndVerify(Byte[]        Ciphertext,
                                       RSAPublicKey  SenderRSAPublicKey)
        {

            var rsaBlocksize      = algorithmSpec.CipherBlockSize;
            var usableBlocksize   = algorithmSpec.UsableBlockSize;

            if (Ciphertext.Length % rsaBlocksize != 0)
                throw new Exception("input length doesn't fit with key size");

            var numBlocks         = Ciphertext.Length / rsaBlocksize; // because of previous check, this is clean
            var decryptedLength   = Ciphertext.Length;                 // same

            var decrypted         = new Byte[numBlocks * usableBlocksize];

            // decrypt
            cipher.InitRSAPublicKey(CipherMode.DECRYPT_MODE, SenderRSAPublicKey, new SecureRandom());

            // we're to process the blocks ourselves.
            var i                 = numBlocks;
            var inputOffset       = 0;
            var outputOffset      = 0;

            while (i > 0)
            {

                cipher.doFinal(Ciphertext, inputOffset, rsaBlocksize, decrypted, outputOffset);

                inputOffset  += rsaBlocksize;
                outputOffset += usableBlocksize;

                i--;

            }

            // now validate padding and extract payload
            var payload = integrityPaddingInstance.CheckAndExtract(decrypted);

            // cleanup as far as possible
            //Arrays.fill(decrypted, (byte) 0x00);

            // return result
            return payload;

        }

        #endregion


    }

}
