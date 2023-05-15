
#region Usings

using Org.BouncyCastle.Asn1.IsisMtt.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;
using System.IO;
using System.Net.NetworkInformation;
using System.Security.Cryptography.X509Certificates;

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

        // RSA/ECB/NoPadding == default
        // RSA/CBC + IV
        // Everything else should be avoided.

        #region Data

        private readonly AlgorithmSpec                algorithmSpec;
        private readonly RsaEngine                    rsaEngine;
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

            // ChatGPT (GPT-4 2023-05-15) seems really to worry what we are doing here!

            // Please note that using RSA without padding (known as "NoPadding") is highly insecure
            // and should not be used in any situation where secure, cryptographic-strength
            // encryption is needed. It is prone to a number of serious attacks, including
            // straightforward brute-force attacks, as well as more sophisticated mathematical
            // attacks.

            // Again, I can't stress enough that you should not use RSA without padding for any
            // purpose where security is important. It's better to use one of the secure padding
            // options like OAEP or PKCS1.

            // Sure, that comment provides a light-hearted acknowledgment of the security concerns.
            // It's always important to remember that security should be a priority in any code
            // that deals with sensitive data. It's good to add comments in your code to remind
            // anyone who might work on it in the future about the security implications of
            // their choices.

            this.algorithmSpec             = AlgorithmSpec;
            this.rsaEngine                 = new RsaEngine(); // RSA/ECB/NoPadding
            this.integrityPaddingInstance  = new InterleavedIntegrityPadding(algorithmSpec.UsableBlockSize);

        }

        #endregion


        //ToDo(ahzf): RSA IIP does not yet use the correct RSA key data structure!


        #region PadEncryptAndPackage(Plaintext,  OurRSAPrivateKey)

        /// <summary>
        /// Pad encrypt and package.
        /// </summary>
        /// <param name="Plaintext">A plaintext.</param>
        /// <param name="OurRSAPrivateKey">A RSA private key.</param>
        public Byte[] PadEncryptAndPackage(Byte[]         Plaintext,
                                           RSAPrivateKey  OurRSAPrivateKey)
        {

            var rsaBlocksize     = algorithmSpec.CipherBlockSize;
            var usableBlocksize  = algorithmSpec.UsableBlockSize;

            var padded           = integrityPaddingInstance.PerformPaddingWithAllocation(Plaintext);
            //assert (padded.length % usable_blocksize == 0); // if not, our padding has a bug

            // Here we init RSA with the PRIVATE KEY!
            // So just the other way round as normally done!
            rsaEngine.Init(true, OurRSAPrivateKey.Key); 
            //assert (rsaPrivKey.getModulus().bitLength() == algorithmSpec.getKeySizeInBit()); // must match expected size

            // rsa will support single blocks only, so we have to split ourselves.
            var inputLength      = (UInt32) padded.Length;
            var outputLength     = inputLength  / usableBlocksize * rsaBlocksize; // scaling from one to the other
            var encrypted        = new Byte[outputLength];
            var numBlocksInput   = outputLength / rsaBlocksize;


            // ChatGPT (GPT-4 2023-05-15) seems really to worry what we are doing here!
            //
            // The ProcessBlock method in BouncyCastle's RsaEngine can be called multiple times.
            // However, because RSA operates on fixed-size blocks (the size of which is determined
            // by the key size), each call to ProcessBlock will independently encrypt (or decrypt,
            // depending on how the engine was initialized) a block of data.
            //
            // If you call ProcessBlock multiple times with different parts of your data, it will
            // result in each part being encrypted separately.This could lead to an increased
            // vulnerability to certain types of attacks, especially if you're not using a
            // padding scheme (which you're not, in this case).
            //
            // Moreover, you need to be careful about the size of the data you're encrypting.
            // The input must be smaller than the modulus size of the RSA key, otherwise, an
            // exception will be thrown. In the case of a 2048-bit RSA key, the maximum size
            // is 256 bytes. If your data is larger than this, it must be broken up into
            // smaller chunks that fit within this limit, and each chunk can be encrypted
            // individually.
            //
            // In summary, you can call ProcessBlock multiple times, but be aware of the security
            // implications and data size restrictions.


            //for (var i = 0U; i < numBlocksInput; i++)
            //    cipher.doFinal(padded,
            //                   (Int32) (i * usableBlocksize),
            //                   (Int32) usableBlocksize,
            //                   encrypted,
            //                   (Int32) (i * rsaBlocksize)); // different blocksizes. Details matter.

            for (var i = 0U; i < numBlocksInput; i++)
            {

                var tmp = rsaEngine.ProcessBlock(padded,
                                                 (Int32) (i * usableBlocksize),
                                                 (Int32) usableBlocksize); // different blocksizes. Details matter.

                Array.Copy(tmp,
                           0,
                           encrypted,
                           (Int32) (i * rsaBlocksize),
                           tmp.Length);

            }

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


            // ChatGPT (GPT-4 2023-05-15) seems really to worry what we are doing here!
            //
            // Again, I should emphasize that RSA without padding is insecure and should
            // not be used for any purpose where secure encryption is required.
            // However, for educational purposes, here's how to decrypt a byte array
            // using RSA 2048 with BouncyCastle in C#.

            //cipher.InitRSAPublicKey(CipherMode.DECRYPT_MODE, SenderRSAPublicKey, new SecureRandom());
            rsaEngine.Init(false, SenderRSAPublicKey.Key);


            var i                 = numBlocks;
            var inputOffset       = 0U;
            var outputOffset      = 0U;

            while (i > 0)
            {

                // cipher.doFinal(Ciphertext,
                //                (Int32) inputOffset,
                //                (Int32) rsaBlocksize,
                //                decrypted,
                //                (Int32) outputOffset);

                var tmp = rsaEngine.ProcessBlock(Ciphertext,
                                                 (Int32) inputOffset,
                                                 (Int32) rsaBlocksize);

                Array.Copy(tmp,
                           0,
                           decrypted,
                           (Int32) outputOffset,
                           tmp.Length);

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
