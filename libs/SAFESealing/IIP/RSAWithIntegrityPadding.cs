
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
    /// Performs Interleaved Integrity Padding using RSA/ECB/NoPadding.
    /// 
    /// Here we use the private and public keys of RSA with swapped roles.
    /// This "reverse operation" has a special use case: digital signatures.
    /// 
    /// When you "encrypt" a message (or more commonly, a hash of a message)
    /// with your private key, anyone can "decrypt" it with your public key,
    /// thus verifying that the message came from you and hasn't been tampered
    /// with. This is because only you should have access to your private key.
    /// This operation doesn't provide confidentiality (since anyone with your
    /// public key can "decrypt" the message), but it does provide a level of
    /// authenticity and non-repudiation.
    /// 
    /// Caveat: the MSB of an RSA block is unavailable, since it must be set;
    /// some SecurityProvider implementations may chose to block a byte or more.
    /// </summary>
    public class RSAWithIntegrityPadding
    {

        // RSA/ECB/NoPadding == default
        // RSA/CBC + IV ???
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

            var padded          = integrityPaddingInstance.PerformPadding(Plaintext);

            if (padded.Length % algorithmSpec.UsableBlockSize != 0)
                throw new Exception("The length of the given plaintext doesn't match the key size!");


            // Here we init RSA with the PRIVATE KEY!
            // So just the other way round as normally done
            // in order to use RSA as a digital signature signer!
            rsaEngine.Init(true,
                           OurRSAPrivateKey.Key); 

            // RSA will support single blocks only...
            // therefore, we have to split them ourselves.
            var outputLength    = (UInt64) (padded.Length / algorithmSpec.UsableBlockSize * algorithmSpec.CipherBlockSize);
            var encrypted       = new Byte[outputLength];
            var numBlocksInput  = outputLength / algorithmSpec.CipherBlockSize;


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

            for (var i = 0U; i < numBlocksInput; i++)
            {

                var tmp = rsaEngine.ProcessBlock(padded,
                                                 (Int32) (i * algorithmSpec.UsableBlockSize),
                                                 (Int32)      algorithmSpec.UsableBlockSize); // different blocksizes. Details matter.

                Array.Copy(tmp,
                           0,
                           encrypted,
                           (Int32) (i * algorithmSpec.CipherBlockSize),
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

            if (Ciphertext.Length % algorithmSpec.CipherBlockSize != 0)
                throw new Exception("The length of the given ciphertext doesn't match the key size!");

            var numBlocks     = Ciphertext.Length / algorithmSpec.CipherBlockSize;
            var decrypted     = new Byte[numBlocks * algorithmSpec.UsableBlockSize];

            // Here we init RSA with the PUBLIC KEY!
            // So just the other way round as normally done
            // in order to use RSA as a digital signature verifier!
            rsaEngine.Init(false,
                           SenderRSAPublicKey.Key);


            // ChatGPT (GPT-4 2023-05-15) seems really to worry what we are doing here!
            //
            // Again, I should emphasize that RSA without padding is insecure and should
            // not be used for any purpose where secure encryption is required.
            // However, for educational purposes, here's how to decrypt a byte array
            // using RSA 2048 with BouncyCastle in C#.

            var i             = numBlocks;
            var inputOffset   = 0U;
            var outputOffset  = 0U;

            while (i > 0)
            {

                var tmp = rsaEngine.ProcessBlock(Ciphertext,
                                                 (Int32) inputOffset,
                                                 (Int32) algorithmSpec.CipherBlockSize);

                Array.Copy(tmp,
                           0,
                           decrypted,
                           (Int32) outputOffset,
                           tmp.Length);

                inputOffset  += algorithmSpec.CipherBlockSize;
                outputOffset += algorithmSpec.UsableBlockSize;

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
