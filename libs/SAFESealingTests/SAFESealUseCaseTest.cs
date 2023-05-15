
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

    public class SAFESealUseCaseTest
    {

        #region Data

        private ECPrivateKeyParameters?   senderECPrivateKey;
        private ECPublicKeyParameters?    senderECPublicKey;
        private ECPrivateKeyParameters?   recipientECPrivateKey;
        private ECPublicKeyParameters?    recipientECPublicKey;

        private AsymmetricCipherKeyPair?  rsaKeyPair;
        private RSAPrivateKey?            rsaPrivateKey;
        private RSAPublicKey?             rsaPublicKey;

        #endregion

        #region Setup()

        [OneTimeSetUp]
        public void Setup()
        {
            GenerateECKeyPairs("secp256r1");
            GenerateRSAKeyPair(2048);
        }

        #endregion


        #region GenerateECKeyPairs(CurveName)

        public void GenerateECKeyPairs(String CurveName)
        {

            var ecParameters          = ECNamedCurveTable.GetByName(CurveName);
            var ecDomainParameters    = new ECDomainParameters(ecParameters.Curve,
                                                               ecParameters.G,
                                                               ecParameters.N,
                                                               ecParameters.H,
                                                               ecParameters.GetSeed());

            var ecKeyPairGenerator    = new ECKeyPairGenerator("EC");
            ecKeyPairGenerator.Init(new ECKeyGenerationParameters(ecDomainParameters,
                                                                  new SecureRandom()));

            var keyPairA = ecKeyPairGenerator.GenerateKeyPair();
            this.senderECPrivateKey     = (ECPrivateKeyParameters) keyPairA.Private;
            this.senderECPublicKey      = (ECPublicKeyParameters)  keyPairA.Public;

            var keyPairB = ecKeyPairGenerator.GenerateKeyPair();
            this.recipientECPrivateKey  = (ECPrivateKeyParameters) keyPairB.Private;
            this.recipientECPublicKey   = (ECPublicKeyParameters)  keyPairB.Public;

        }

        #endregion

        #region  GenerateRSAKeyPair(KeySize)

        public void GenerateRSAKeyPair(Int32 KeySize)
        {

            var rsaKeyPairGenerator = new RsaKeyPairGenerator();

            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(),
                                                                 KeySize));

            this.rsaKeyPair     = rsaKeyPairGenerator.GenerateKeyPair();

            // Automagic implicit conversion! :)
            this.rsaPrivateKey  = this.rsaKeyPair;
            this.rsaPublicKey   = this.rsaKeyPair;

        }

        #endregion


        #region UseCaseTestWithECDHE()

        [Test]
        public void UseCaseTestWithECDHE()
        {

            Assert.IsNotNull(senderECPrivateKey);
            Assert.IsNotNull(senderECPublicKey);
            Assert.IsNotNull(recipientECPrivateKey);
            Assert.IsNotNull(recipientECPublicKey);

            if (senderECPrivateKey    is not null &&
                senderECPublicKey     is not null &&
                recipientECPrivateKey is not null &&
                recipientECPublicKey  is not null)
            {

                var plaintext1  = Encoding.UTF8.GetBytes("S.A.F.E. e.V.");
                var testNonce   = BitConverter.GetBytes(23); // DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // SENDER performs sealing
                var sealedData  = new SAFESealSealer().Seal(senderECPrivateKey,
                                                            recipientECPublicKey,
                                                            plaintext1,
                                                            testNonce);

                // RECIPIENT performs revealing
                var plaintext2  = new SAFESealRevealer().Reveal(senderECPublicKey,
                                                                recipientECPrivateKey,
                                                                sealedData);

                Assert.AreEqual(plaintext1, plaintext2);

            }

        }

        #endregion

        #region UseCaseTestWithRSA()

        [Test]
        public void UseCaseTestWithRSA()
        {

            Assert.IsNotNull(rsaKeyPair);
            Assert.IsNotNull(rsaPrivateKey);
            Assert.IsNotNull(rsaPublicKey);

            if (rsaKeyPair    is not null &&
                rsaPrivateKey is not null &&
                rsaPublicKey  is not null)
            {

                var plaintext1  = Encoding.UTF8.GetBytes("S.A.F.E. e.V.");

                // SENDER performs sealing
                var sealedData  = new SAFESealSealer().Seal(rsaPrivateKey,
                                                            plaintext1);

                // RECIPIENT performs revealing
                var plaintext2  = new SAFESealRevealer().Reveal(rsaPublicKey,
                                                                sealedData);

                Assert.AreEqual(plaintext1, plaintext2);

            }

        }

        #endregion


    }

}
