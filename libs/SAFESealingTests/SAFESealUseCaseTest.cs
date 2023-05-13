using NUnit.Framework;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using SAFESealing;
using System.Security.Cryptography;
using System.Text;

namespace SAFESealingTests
{
    public class SAFESealUseCaseTest
    {

     //   private static SecureRandom rng;

        private ECPrivateKeyParameters   senderPrivateKey;
        private ECPublicKeyParameters    senderPublicKey;
        private ECPrivateKeyParameters   recipientPrivateKey;
        private ECPublicKeyParameters    recipientPublicKey;

        private AsymmetricCipherKeyPair  rsaKeyPair;


        [Test]
        public void UseCaseTestWithECDHE()
        {

            var testPayload  = Encoding.UTF8.GetBytes("SAFE eV");
            var testUnique   = (Int64) 23; // DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // SENDER performs sealing
            var uwe              = new SAFESealSealer(true);
            var sealedData       = uwe.Seal(senderPrivateKey,
                                            recipientPublicKey,
                                            testPayload,
                                            testUnique);

            // RECIPIENT performs revealing
            var revealer         = new SAFESealRevealer(true);
            var receivedPayload  = revealer.Reveal(senderPublicKey,
                                                   recipientPrivateKey,
                                                   sealedData);

            Assert.AreEqual(testPayload, receivedPayload);

        }


        [OneTimeSetUp]
        public void Setup()
        {
            GenerateECKeyPairs("secp256r1");
        }


        public void GenerateECKeyPairs(String curveName)
        {

            //    // this is the relation between the two: the named ones are a special case
            var namedParameterSpec  = ECNamedCurveTable.GetByName(curveName);
            //// this is the general set, for almost all (in this representation, that is)
            var domainParams        = new ECDomainParameters(namedParameterSpec.Curve,
                                                             namedParameterSpec.G,
                                                             namedParameterSpec.N,
                                                             namedParameterSpec.H,
                                                             namedParameterSpec.GetSeed());

            var srandom    = new SecureRandom();
            var generator  = new ECKeyPairGenerator("EC");
            generator.Init(new ECKeyGenerationParameters(domainParams, srandom));

            var keyPairA = generator.GenerateKeyPair();
            var keyPairB = generator.GenerateKeyPair();

            this.senderPrivateKey       = (ECPrivateKeyParameters) keyPairA.Private;
            this.senderPublicKey        = (ECPublicKeyParameters)  keyPairA.Public;

            this.recipientPrivateKey    = (ECPrivateKeyParameters) keyPairB.Private;
            this.recipientPublicKey     = (ECPublicKeyParameters)  keyPairB.Public;

        }


        public AsymmetricCipherKeyPair GenerateRSAKeyPair(int keySize)
        {

            var rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
            return rsaKeyPairGenerator.GenerateKeyPair();

        }

    }

}
