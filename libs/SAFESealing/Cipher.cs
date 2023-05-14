using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

namespace SAFESealing
{

    public enum CipherMode
    {
        ENCRYPT_MODE,
        DECRYPT_MODE

    }

    public class Cipher : IAsymmetricBlockCipher
    {

        private ICryptoTransform aesCipher;

        public Aes     AES          { get; }
        public Byte[]  IV           { get; }
        public Int32   BlockSize    { get; }

        public Cipher(Aes AES)
        {
            this.AES        = AES;
            this.IV         = AES.IV;
            this.BlockSize  = AES.BlockSize / 8;
        }


        public void Init(CipherMode    Mode,
                         KeyParameter  SecretKey,
                         SecureRandom  SecureRandom)
        {

            this.AES.Key    = SecretKey.GetKey();
            this.aesCipher  = this.AES.CreateEncryptor();

        }

        public Byte[] DoFinal(Byte[] Cleartext)
        {
            // ToDo(ahzf): aesCipher must be set!
            return aesCipher.TransformFinalBlock(Cleartext, 0, Cleartext.Length);
        }



















        public String AlgorithmName
        {
            get
            {
                return "algo";
            }
        }


        public void Init(Boolean            forEncryption,
                         ICipherParameters  parameters)
        {
            throw new NotImplementedException();
        }

        public Int32 GetInputBlockSize()
        {
            throw new NotImplementedException();
        }

        public Int32 GetOutputBlockSize()
        {
            throw new NotImplementedException();
        }

        public Byte[] ProcessBlock(Byte[] inBuf, Int32 inOff, Int32 inLen)
        {
            throw new NotImplementedException();
        }



        private IAsymmetricBlockCipher BC { get; }

        public Cipher(IAsymmetricBlockCipher BC)
        {
            this.BC = BC;
        }

        public void Init(CipherMode Mode, KeyParameter secretKey)
        {

            

        }


        public void Init(CipherMode Mode, KeyParameter secretKey, IvParameterSpec iv)
        {



        }


        public void Init(CipherMode Mode, RSAPrivateKey OurPrivateKey, SecureRandom rng)
        {



        }

        public void Init(CipherMode Mode, ECPublicKeyParameters PublicKey, SecureRandom rng)
        {



        }






        public Byte[] doFinal(Byte[] padded,
                              Int32  usable_blocksize,
                              Int32  usable_blocksize2,
                              Byte[] encrypted,
                              Int32  RSA_blocksize) // different blocksizes. Details matter.
        {
            return Array.Empty<Byte>();
        }







    }

}
