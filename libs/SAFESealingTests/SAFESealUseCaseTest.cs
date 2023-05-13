
#region Usings

using System.Text;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

using NUnit.Framework;

#endregion

namespace SAFESealing.Tests
{

    public class SAFESealUseCaseTest
    {

        #region Data

        private ECPrivateKeyParameters?   senderPrivateKey;
        private ECPublicKeyParameters?    senderPublicKey;
        private ECPrivateKeyParameters?   recipientPrivateKey;
        private ECPublicKeyParameters?    recipientPublicKey;

        private AsymmetricCipherKeyPair?  rsaKeyPair;

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
            this.senderPrivateKey     = (ECPrivateKeyParameters) keyPairA.Private;
            this.senderPublicKey      = (ECPublicKeyParameters)  keyPairA.Public;

            var keyPairB = ecKeyPairGenerator.GenerateKeyPair();
            this.recipientPrivateKey  = (ECPrivateKeyParameters) keyPairB.Private;
            this.recipientPublicKey   = (ECPublicKeyParameters)  keyPairB.Public;

        }

        #endregion

        #region  GenerateRSAKeyPair(KeySize)

        public AsymmetricCipherKeyPair GenerateRSAKeyPair(Int32 KeySize)
        {

            var rsaKeyPairGenerator = new RsaKeyPairGenerator();

            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(),
                                                                 KeySize));

            return rsaKeyPair = rsaKeyPairGenerator.GenerateKeyPair();

        }

        #endregion


        #region UseCaseTestWithECDHE()

        [Test]
        public void UseCaseTestWithECDHE()
        {

            Assert.IsNotNull(senderPrivateKey);
            Assert.IsNotNull(recipientPublicKey);
            Assert.IsNotNull(senderPublicKey);
            Assert.IsNotNull(recipientPrivateKey);

            var testPayload      = Encoding.UTF8.GetBytes("SAFE eV");
            var testUnique       = (Int64) 23; // DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // SENDER performs sealing
            var uwe              = new SAFESealSealer(true);
            var sealedData       = uwe.Seal(senderPrivateKey!,
                                            recipientPublicKey!,
                                            testPayload,
                                            testUnique);

            // RECIPIENT performs revealing
            var revealer         = new SAFESealRevealer(true);
            var receivedPayload  = revealer.Reveal(senderPublicKey!,
                                                   recipientPrivateKey!,
                                                   sealedData);

            Assert.AreEqual(testPayload, receivedPayload);

        }

        #endregion


    }

}
