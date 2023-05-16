
#region Usings

using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing.Tests
{

    /// <summary>
    /// Tests for SAFE EC Seals.
    /// </summary>
    public class SAFE_EC_Seal_Tests
    {

        #region Data

        private ECPrivateKeyParameters?  senderECPrivateKey;
        private ECPublicKeyParameters?   senderECPublicKey;
        private ECPrivateKeyParameters?  recipientECPrivateKey;
        private ECPublicKeyParameters?   recipientECPublicKey;

        #endregion

        #region Setup()

        [OneTimeSetUp]
        public void Setup()
        {

            var ecParameters            = ECNamedCurveTable.GetByName("secp256r1");
            var ecDomainParameters      = new ECDomainParameters(ecParameters.Curve,
                                                                 ecParameters.G,
                                                                 ecParameters.N,
                                                                 ecParameters.H,
                                                                 ecParameters.GetSeed());

            var ecKeyPairGenerator      = new ECKeyPairGenerator("EC");
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


        #region EC_Seal_ShortMessage_Test()

        [Test]
        public void EC_Seal_ShortMessage_Test()
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

                var plaintext1  = "S.A.F.E. e.V.";
                var testNonce   = BitConverter.GetBytes(23); // DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // SENDER performs sealing
                var sealedData  = new SAFESealSealer().Seal(senderECPrivateKey,
                                                            recipientECPublicKey,
                                                            Encoding.UTF8.GetBytes(plaintext1),
                                                            testNonce);

                Assert.IsTrue(sealedData.HasNoErrors);


                // RECIPIENT performs revealing
                var plaintext2  = new SAFESealRevealer().Reveal(senderECPublicKey,
                                                                recipientECPrivateKey,
                                                                sealedData);

                Assert.IsTrue  (plaintext2.HasNoErrors);
                Assert.AreEqual(plaintext1, Encoding.UTF8.GetString(plaintext2));

            }

        }

        #endregion


        //ToDo(ahzf): Long messages seem to be broken!
        #region EC_Seal_LongMessage_Test()

        [Test]
        public void EC_Seal_LongMessage_Test()
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

                var plaintext1  = "Stufen\r\nWie jede Blüte welkt und jede Jugend\r\nDem Alter weicht, blüht jede Lebensstufe,\r\nBlüht jede Weisheit auch und jede Tugend\r\nZu ihrer Zeit und darf nicht ewig dauern.\r\nEs muß das Herz bei jedem Lebensrufe\r\nBereit zum Abschied sein und Neubeginne,\r\nUm sich in Tapferkeit und ohne Trauern\r\nIn andre, neue Bindungen zu geben.\r\nUnd jedem Anfang wohnt ein Zauber inne,\r\nDer uns beschützt und der uns hilft, zu leben.\r\n\r\nWir sollen heiter Raum um Raum durchschreiten,\r\nAn keinem wie an einer Heimat hängen,\r\nDer Weltgeist will nicht fesseln uns und engen,\r\nEr will uns Stuf´ um Stufe heben, weiten.\r\nKaum sind wir heimisch einem Lebenskreise\r\nUnd traulich eingewohnt, so droht Erschlaffen;\r\nNur wer bereit zu Aufbruch ist und Reise,\r\nMag lähmender Gewöhnung sich entraffen.\r\n\r\nEs wird vielleicht auch noch die Todesstunde\r\nUns neuen Räumen jung entgegen senden,\r\nDes Lebens Ruf an uns wird niemals enden,\r\nWohlan denn, Herz, nimm Abschied und gesunde!";
                var testNonce   = BitConverter.GetBytes(23); // DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // SENDER performs sealing
                var sealedData  = new SAFESealSealer().Seal(senderECPrivateKey,
                                                            recipientECPublicKey,
                                                            Encoding.UTF8.GetBytes(plaintext1),
                                                            testNonce);

                Assert.IsTrue(sealedData.HasNoErrors);


                // RECIPIENT performs revealing
                var plaintext2  = new SAFESealRevealer().Reveal(senderECPublicKey,
                                                                recipientECPrivateKey,
                                                                sealedData);

                Assert.IsTrue  (plaintext2.HasNoErrors);
                Assert.AreEqual(plaintext1, Encoding.UTF8.GetString(plaintext2));

            }

        }

        #endregion


    }

}
