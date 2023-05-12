using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
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
        public string AlgorithmName => throw new NotImplementedException();

        public String getAlgorithm()

        {
            return "algo";
        }

        public Int32 getBlockSize()
        {
            return 16;
        }

        public Byte[] getIV()
        {
            return Array.Empty<Byte>();
        }

        private IAsymmetricBlockCipher BC { get; }

        public Cipher(IAsymmetricBlockCipher BC)
        {
            this.BC = BC;
        }




        public void Init(CipherMode Mode, KeyParameter secretKey)
        {

            

        }

        public void Init(CipherMode Mode, KeyParameter secretKey, SecureRandom rng)
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



        public Byte[] doFinal(Byte[] dataToEncrypt)
        {
            return Array.Empty<Byte>();
        }


        public Byte[] doFinal(Byte[] padded,
                              Int32  usable_blocksize,
                              Int32  usable_blocksize2,
                              Byte[] encrypted,
                              Int32  RSA_blocksize) // different blocksizes. Details matter.
        {
            return Array.Empty<Byte>();
        }





        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            throw new NotImplementedException();
        }

        public int GetInputBlockSize()
        {
            throw new NotImplementedException();
        }

        public int GetOutputBlockSize()
        {
            throw new NotImplementedException();
        }

        public byte[] ProcessBlock(byte[] inBuf, int inOff, int inLen)
        {
            throw new NotImplementedException();
        }


    }

}
