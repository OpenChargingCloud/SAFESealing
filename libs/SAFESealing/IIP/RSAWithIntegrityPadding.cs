
#region Usings

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// performs RSA/ECB/IIP, chaining provided by the IIP.
    /// 
    /// Caveat: the MSB of an RSA block is unavailable, since it must be set;
    /// some SecurityProvider implementations may chose to block a byte or more.
    /// 
    /// This implementation is compatible with the way BouncyCastle handles this.
    /// Using a different SecurityProvider/JCE may cause issues with block size.
    /// There's settings in the...
    /// </summary>
    public class RSAWithIntegrityPadding
    {

        #region Data

        private readonly AlgorithmSpec                algorithmSpec;
        private readonly Cipher                       cipher;
        private readonly SecureRandom                 rng;
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
        /// Constructor for RSAWithIntegrityPadding.
        /// </summary>
        /// <param name="AlgorithmSpec">The (symmetric) encryption algorithm to be used</param>
        public RSAWithIntegrityPadding(AlgorithmSpec  AlgorithmSpec)
        {

            this.algorithmSpec             = AlgorithmSpec;
            this.cipher                    = CryptoFactory.GetCipherFromCipherSpec(algorithmSpec);
            this.rng                       = new SecureRandom();
            this.integrityPaddingInstance  = new InterleavedIntegrityPadding(algorithmSpec.UsableBlockSize);

        }

        #endregion


        //ToDo(ahzf): RSA IIP does not yet use the correct RSA key data structure!


        #region PadEncryptAndPackage(Cleartext, OurRSAPrivateKey)

        /// <summary>
        /// Pad encrypt and package.
        /// </summary>
        /// <param name="Cleartext">An array of {@link byte} objects</param>
        /// <param name="OurRSAPrivateKey">a {@link java.security.PrivateKey} object</param>
        public Byte[] PadEncryptAndPackage(Byte[]         Cleartext,
                                           RSAPrivateKey  OurRSAPrivateKey)
        {


            var RSA_blocksize     = algorithmSpec.CipherBlockSize;
            var usable_blocksize  = algorithmSpec.UsableBlockSize;

            //ToDo(ahzf): This cast is wrong!
          //  var rsaPrivKey        = (RSAPrivateKey) (Object) OurRSAPrivateKey; // cast checks for correct key type for the algorithms
            //assert (rsaPrivKey.getModulus().bitLength() == algorithmSpec.getKeySizeInBit()); // must match expected size

            // pad
            var padded = integrityPaddingInstance.PerformPaddingWithAllocation(Cleartext);
            //assert (padded.length % usable_blocksize == 0); // if not, our padding has a bug

            // encrypt
            cipher.InitRSAPrivateKey(CipherMode.ENCRYPT_MODE, OurRSAPrivateKey, rng);
            // rsa will support single blocks only, so we have to split ourselves.
            var inputLength     = padded.Length;
            var outputLength    = (inputLength / usable_blocksize) * RSA_blocksize; // scaling from one to the other
            var encrypted       = new byte[outputLength];
            var numBlocksInput  = outputLength / RSA_blocksize;

            for (var i = 0; i < numBlocksInput; i++)
                cipher.doFinal(padded,
                               i * usable_blocksize,
                               usable_blocksize,
                               encrypted,
                               i * RSA_blocksize); // different blocksizes. Details matter.

            // cleanup as far as possible
            //Arrays.fill(padded, (byte) 0x00);

            return encrypted;

        }

        #endregion


        #region DecryptAndVerify(EncryptedData, SenderRSAPublicKey)

        /// <summary>
        /// Decrypt and verify.
        /// </summary>
        /// <param name="EncryptedData">an array of {@link byte} objects</param>
        /// <param name="SenderRSAPublicKey">a {@link java.security.PublicKey} object</param>
        public Byte[] DecryptAndVerify(Byte[]        EncryptedData,
                                       RSAPublicKey  SenderRSAPublicKey)
        {

            var RSA_blocksize     = algorithmSpec.CipherBlockSize;
            var usable_blocksize  = algorithmSpec.UsableBlockSize;

            if (EncryptedData.Length % RSA_blocksize != 0)
                throw new Exception("input length doesn't fit with key size");

            var numBlocks         = EncryptedData.Length / RSA_blocksize; // because of previous check, this is clean
            var decryptedLength   = EncryptedData.Length;                 // same

            var decrypted         = new Byte[numBlocks * usable_blocksize];

            // decrypt
            cipher.InitRSAPublicKey(CipherMode.DECRYPT_MODE, SenderRSAPublicKey, rng);

            // we're to process the blocks ourselves.
            var i             = numBlocks;
            var inputOffset   = 0;
            var outputOffset  = 0;

            while (i > 0)
            {

                cipher.doFinal(EncryptedData, inputOffset, RSA_blocksize, decrypted, outputOffset);

                inputOffset  += RSA_blocksize;
                outputOffset += usable_blocksize;

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
