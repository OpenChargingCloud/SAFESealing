
#region Usings

using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing.Tests
{

    public class SAFE_RSA_Seal_Tests
    {

        #region Data

        private AsymmetricCipherKeyPair?  rsaKeyPair;
        private RSAPrivateKey?            rsaPrivateKey;
        private RSAPublicKey?             rsaPublicKey;

        #endregion

        #region Setup()

        [OneTimeSetUp]
        public void Setup()
        {

            var rsaKeyPairGenerator = new RsaKeyPairGenerator();

            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(),
                                                                 2048));

            this.rsaKeyPair     = rsaKeyPairGenerator.GenerateKeyPair();

            // Automagic implicit conversion! :)
            this.rsaPrivateKey  = this.rsaKeyPair;
            this.rsaPublicKey   = this.rsaKeyPair;

        }

        #endregion


        #region RSA_Seal_ShortMessage_Test()

        [Test]
        public void RSA_Seal_ShortMessage_Test()
        {

            Assert.IsNotNull(rsaKeyPair);
            Assert.IsNotNull(rsaPrivateKey);
            Assert.IsNotNull(rsaPublicKey);

            if (rsaKeyPair    is not null &&
                rsaPrivateKey is not null &&
                rsaPublicKey  is not null)
            {

                var plaintext1  = "S.A.F.E. e.V.";

                // SENDER performs sealing
                var sealedData  = new SAFESealSealer().Seal(rsaPrivateKey,
                                                            Encoding.UTF8.GetBytes(plaintext1));

                // RECIPIENT performs revealing
                var plaintext2  = new SAFESealRevealer().Reveal(rsaPublicKey,
                                                                sealedData);

                Assert.AreEqual(plaintext1, Encoding.UTF8.GetString(plaintext2));

            }

        }

        #endregion


    }

}
