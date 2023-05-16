
#region Usings

using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// This is the core implementation of Interleaved Integrity Padding.
    /// 
    /// Use it with: AES/ECB or AES/CBC
    /// 
    /// NEVER use streaming ciphers which just XOR their stream in combination
    /// with this padding like: */CFB, */OFB, */CTR, */GCM
    /// </summary>
    public class SymmetricEncryptionWithIntegrityPadding
    {

        #region Data

        private readonly BufferedBlockCipher?        bufferedBlockCipher;
        private readonly PaddedBufferedBlockCipher?  paddedBufferedBlockCipher;

        #endregion

        #region Properties

        public String                       Algorithm
            => bufferedBlockCipher?.      AlgorithmName ??
               paddedBufferedBlockCipher?.AlgorithmName ??
               String.Empty;

        public Boolean                      IVRequired                  { get; }

        public Byte[]                       IV                          { get; private set; } = Array.Empty<Byte>();

        public UInt16                       CipherBlockSize             { get; }

        public InterleavedIntegrityPadding  IntegrityPaddingInstance    { get; }

        #endregion


        #region Constructor(s)

        private SymmetricEncryptionWithIntegrityPadding(BufferedBlockCipher  BufferedBlockCipher,
                                                        UInt16               CipherBlockSize,
                                                        Boolean              IVRequired   = false)
        {

            this.bufferedBlockCipher        = BufferedBlockCipher;
            this.CipherBlockSize            = CipherBlockSize;
            this.IVRequired                 = IVRequired;
            this.IntegrityPaddingInstance   = new InterleavedIntegrityPadding(CipherBlockSize);

        }

        private SymmetricEncryptionWithIntegrityPadding(PaddedBufferedBlockCipher  PaddedBufferedBlockCipher,
                                                        UInt16                     CipherBlockSize,
                                                        Boolean                    IVRequired   = false)
        {

            this.paddedBufferedBlockCipher  = PaddedBufferedBlockCipher;
            this.CipherBlockSize            = CipherBlockSize;
            this.IVRequired                 = IVRequired;
            this.IntegrityPaddingInstance   = new InterleavedIntegrityPadding(CipherBlockSize);

        }

        #endregion


        #region AES_ECB_PKCS7

        /// <summary>
        /// Create AES-256 cipher with ECB mode and PKCS7 padding
        /// </summary>
        public static SymmetricEncryptionWithIntegrityPadding AES_ECB_PKCS7
        {
            get
            {

                var aesEngine = new AesEngine();

                return new SymmetricEncryptionWithIntegrityPadding(
                           new PaddedBufferedBlockCipher(aesEngine),
                           (UInt16) aesEngine.GetBlockSize(),
                           IVRequired: false
                       );

            }
        }

        #endregion

        #region AES_ECB_NoPKCS7

        /// <summary>
        /// Create AES-256 cipher with ECB mode and no padding
        /// (no padding might be dangerous!)
        /// </summary>
        public static SymmetricEncryptionWithIntegrityPadding AES_ECB_NoPKCS7
        {
            get
            {

                var aesEngine = new AesEngine();

                return new SymmetricEncryptionWithIntegrityPadding(
                           new BufferedBlockCipher(aesEngine),
                           (UInt16) aesEngine.GetBlockSize(),
                           IVRequired: false
                       );

            }
        }

        #endregion


        #region AES_CBC_PKCS7

        /// <summary>
        /// Create AES-256 cipher with CBC mode and PKCS7 padding
        /// </summary>
        public static SymmetricEncryptionWithIntegrityPadding AES_CBC_PKCS7
        {
            get
            {

                var aesEngine = new AesEngine();

                return new SymmetricEncryptionWithIntegrityPadding(
                           new PaddedBufferedBlockCipher(new CbcBlockCipher(aesEngine)),
                           (UInt16) aesEngine.GetBlockSize(),
                           IVRequired: true
                       );

            }
        }

        #endregion

        #region AES_CBC_NoPKCS7

        /// <summary>
        /// Create AES-256 cipher with CBC mode and no padding
        /// (no padding might be dangerous!)
        /// </summary>
        public static SymmetricEncryptionWithIntegrityPadding AES_CBC_NoPKCS7
        {
            get
            {

                var aesEngine = new AesEngine();

                return new SymmetricEncryptionWithIntegrityPadding(
                           new BufferedBlockCipher(new CbcBlockCipher(aesEngine)),
                           (UInt16) aesEngine.GetBlockSize(),
                           IVRequired: true
                       );

            }
        }

        #endregion


        #region EncryptOnly  (Plaintext, SecretKey)

        /// <summary>
        /// Encrypt only.
        /// </summary>
        /// <param name="Plaintext">A plaintext.</param>
        /// <param name="SecretKey">A crypto key.</param>
        public ByteArray EncryptOnly(Byte[]        Plaintext,
                                     KeyParameter  SecretKey)
        {

            #region Data

            if (Plaintext.Length == 0)
                return ByteArray.Error("Invalid plaintext!");

            if (SecretKey.GetKey().Length != 32)
                return ByteArray.Error("Secret key must be exactly 256 bits (32 bytes) long!");

            #endregion

            #region Generate an initialization vector, when required...

            if (IVRequired && IV.Length == 0)
            {

                // 16 bytes for a 128-bit IV
                IV = new Byte[16];

                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(IV);

            }

            #endregion

            #region Buffered Block Cipher

            if (bufferedBlockCipher is not null)
            {

                // true for encryption
                bufferedBlockCipher.Init(true,
                                         IVRequired
                                             ? new ParametersWithIV(
                                                   SecretKey,
                                                   IV
                                               )
                                             : SecretKey);

                var output        = new Byte[bufferedBlockCipher.GetOutputSize(Plaintext.Length)];
                var outputLength  = bufferedBlockCipher.ProcessBytes(Plaintext, 0, Plaintext.Length, output, 0);
                bufferedBlockCipher.DoFinal(output, outputLength);

                return ByteArray.Ok(output);

            }

            #endregion

            #region Padded Buffered Block Cipher

            else if (paddedBufferedBlockCipher is not null)
            {

                // true for encryption
                paddedBufferedBlockCipher.Init(true,
                                               IVRequired
                                                   ? new ParametersWithIV(
                                                         SecretKey,
                                                         IV
                                                     )
                                                   : SecretKey);

                var output        = new byte[paddedBufferedBlockCipher.GetOutputSize(Plaintext.Length)];
                var outputLength  = paddedBufferedBlockCipher.ProcessBytes(Plaintext, 0, Plaintext.Length, output, 0);
                paddedBufferedBlockCipher.DoFinal(output, outputLength);

                return ByteArray.Ok(output);

            }

            #endregion

            else
                return ByteArray.Error("No cipher available!");

        }

        #endregion

        #region PadAndEncrypt(Plaintext, SecretKey)

        /// <summary>
        /// Pad and encrypt.
        /// </summary>
        /// <param name="Plaintext">A plaintext.</param>
        /// <param name="SecretKey">A crypto key.</param>
        public ByteArray PadAndEncrypt(Byte[]        Plaintext,
                                       KeyParameter  SecretKey)
        {

            var padded = IntegrityPaddingInstance.PerformPadding(Plaintext);

            if (padded.HasErrors)
                return ByteArray.Error("Invalid padding!");

            return EncryptOnly(padded,
                               SecretKey);

        }

        #endregion


        #region DecryptAndCheck(Ciphertext, SecretKey, InitializationVector = null)

        /// <summary>
        /// Decrypt and check.
        /// </summary>
        /// <param name="Ciphertext">A ciphertext.</param>
        /// <param name="SecretKey">A crypto key.</param>
        /// <param name="InitializationVector">An optional cryptographic initialization vector.</param>
        public ByteArray DecryptAndCheck(Byte[]        Ciphertext,
                                         KeyParameter  SecretKey,
                                         Byte[]?       InitializationVector   = null)
        {

            #region Data

            if (Ciphertext.Length == 0)
                return ByteArray.Error("Invalid ciphertext!");

            if (SecretKey.GetKey().Length != 32)
                return ByteArray.Error("Key must be 256 bits (32 bytes) long!");

            #endregion

            #region Buffered Block Cipher

            if (bufferedBlockCipher is not null)
            {

                // false for decryption
                bufferedBlockCipher.Init(false,
                                         IVRequired
                                             ? new ParametersWithIV(
                                                   SecretKey,
                                                   InitializationVector ?? Array.Empty<Byte>()
                                               )
                                             : SecretKey);

                var output        = new Byte[bufferedBlockCipher.GetOutputSize(Ciphertext.Length)];
                var outputLength  = bufferedBlockCipher.ProcessBytes(Ciphertext, 0, Ciphertext.Length, output, 0);
                bufferedBlockCipher.DoFinal(output, outputLength);

                return IntegrityPaddingInstance.VerifyAndExtract(output);

            }

            #endregion

            #region Padded Buffered Block Cipher

            else if (paddedBufferedBlockCipher is not null &&
                     InitializationVector      is not null &&
                     InitializationVector.Length > 0)
            {

                // false for decryption
                paddedBufferedBlockCipher.Init(false,
                                               IVRequired
                                                   ? new ParametersWithIV(
                                                         SecretKey,
                                                         InitializationVector ?? Array.Empty<Byte>()
                                                     )
                                                   : SecretKey);

                var output        = new Byte[paddedBufferedBlockCipher.GetOutputSize(Ciphertext.Length)];
                var outputLength  = paddedBufferedBlockCipher.ProcessBytes(Ciphertext, 0, Ciphertext.Length, output, 0);
                paddedBufferedBlockCipher.DoFinal(output, outputLength);

                return IntegrityPaddingInstance.VerifyAndExtract(output);

            }

            #endregion

            else
                return ByteArray.Error("No cipher available!");

        }

        #endregion


    }

}
