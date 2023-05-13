using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SAFESealing
{

    public enum CipherMode
    {
        ENCRYPT_MODE,
        DECRYPT_MODE

    }

    public class Cipher : IAsymmetricBlockCipher
    {
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


        public System.Security.Cryptography.Aes AES { get; }

        public Cipher(System.Security.Cryptography.Aes AES)
        {
            this.AES = AES;
        }



        public Int32 BlockSize
        {
            get
            {
                return this.AES.BlockSize / 8;
            }
        }

        public Byte[] IV
        {
            get
            {
                return Array.Empty<Byte>();
            }
        }

        private IAsymmetricBlockCipher BC { get; }

        public Cipher(IAsymmetricBlockCipher BC)
        {
            this.BC = BC;
        }




        public void Init(CipherMode Mode, KeyParameter secretKey)
        {

            

        }

        private ICryptoTransform aesCipher;

        public void Init(CipherMode Mode, KeyParameter secretKey, SecureRandom rng)
        {
            this.AES.Key  = secretKey.GetKey();
            aesCipher     = this.AES.CreateEncryptor();
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



        public Byte[] DoFinal(Byte[] Cleartext)
        {
            return aesCipher.TransformFinalBlock(Cleartext, 0, Cleartext.Length);
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
