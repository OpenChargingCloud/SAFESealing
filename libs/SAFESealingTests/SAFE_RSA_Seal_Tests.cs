
#region Usings

using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;

#endregion

namespace SAFESealing.Tests
{

    /// <summary>
    /// Tests for SAFE RSA Seals.
    /// </summary>
    public class SAFE_RSA_Seal_Tests
    {

        #region Data

        private AsymmetricCipherKeyPair?  rsa2048_KeyPair;
        private RSAPrivateKey?            rsa2048_PrivateKey;
        private RSAPublicKey?             rsa2048_PublicKey;

        private AsymmetricCipherKeyPair?  rsa4096_KeyPair;
        private RSAPrivateKey?            rsa4096_PrivateKey;
        private RSAPublicKey?             rsa4096_PublicKey;

        #endregion

        #region Setup()

        [OneTimeSetUp]
        public void Setup()
        {

            var rsa2048_KeyPairGenerator = new RsaKeyPairGenerator();

            rsa2048_KeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(),
                                                                      2048));

            this.rsa2048_KeyPair     = rsa2048_KeyPairGenerator.GenerateKeyPair();

            // Automagic implicit conversion! :)
            this.rsa2048_PrivateKey  = this.rsa2048_KeyPair;
            this.rsa2048_PublicKey   = this.rsa2048_KeyPair;


            var rsa4096_KeyPairGenerator = new RsaKeyPairGenerator();

            rsa4096_KeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(),
                                                                      4096));

            this.rsa4096_KeyPair     = rsa4096_KeyPairGenerator.GenerateKeyPair();

            // Automagic implicit conversion! :)
            this.rsa4096_PrivateKey  = this.rsa4096_KeyPair;
            this.rsa4096_PublicKey   = this.rsa4096_KeyPair;

        }

        #endregion


        #region RSA2048_Seal_ShortMessage_Test()

        [Test]
        public void RSA2048_Seal_ShortMessage_Test()
        {

            Assert.IsNotNull(rsa2048_KeyPair);
            Assert.IsNotNull(rsa2048_PrivateKey);
            Assert.IsNotNull(rsa2048_PublicKey);

            if (rsa2048_KeyPair    is not null &&
                rsa2048_PrivateKey is not null &&
                rsa2048_PublicKey  is not null)
            {

                var plaintext1  = "S.A.F.E. e.V.";

                // SENDER performs sealing
                var sealedData  = new SAFESealSealer().Seal(rsa2048_PrivateKey,
                                                            Encoding.UTF8.GetBytes(plaintext1));

                Assert.IsTrue(sealedData.HasNoErrors);


                // RECIPIENT performs revealing
                var plaintext2  = new SAFESealRevealer().Reveal(rsa2048_PublicKey,
                                                                sealedData);

                Assert.IsTrue  (plaintext2.HasNoErrors);
                Assert.AreEqual(plaintext1, Encoding.UTF8.GetString(plaintext2));

            }

        }

        #endregion

        //ToDo(ahzf): Long messages seem to be broken!
        #region RSA2048_Seal_LongMessage_Test()

        [Test]
        public void RSA2048_Seal_LongMessage_Test()
        {

            Assert.IsNotNull(rsa2048_KeyPair);
            Assert.IsNotNull(rsa2048_PrivateKey);
            Assert.IsNotNull(rsa2048_PublicKey);

            if (rsa2048_KeyPair    is not null &&
                rsa2048_PrivateKey is not null &&
                rsa2048_PublicKey  is not null)
            {

                var plaintext1  = "Stufen\r\nWie jede Blüte welkt und jede Jugend\r\nDem Alter weicht, blüht jede Lebensstufe,\r\nBlüht jede Weisheit auch und jede Tugend\r\nZu ihrer Zeit und darf nicht ewig dauern.\r\nEs muß das Herz bei jedem Lebensrufe\r\nBereit zum Abschied sein und Neubeginne,\r\nUm sich in Tapferkeit und ohne Trauern\r\nIn andre, neue Bindungen zu geben.\r\nUnd jedem Anfang wohnt ein Zauber inne,\r\nDer uns beschützt und der uns hilft, zu leben.\r\n\r\nWir sollen heiter Raum um Raum durchschreiten,\r\nAn keinem wie an einer Heimat hängen,\r\nDer Weltgeist will nicht fesseln uns und engen,\r\nEr will uns Stuf´ um Stufe heben, weiten.\r\nKaum sind wir heimisch einem Lebenskreise\r\nUnd traulich eingewohnt, so droht Erschlaffen;\r\nNur wer bereit zu Aufbruch ist und Reise,\r\nMag lähmender Gewöhnung sich entraffen.\r\n\r\nEs wird vielleicht auch noch die Todesstunde\r\nUns neuen Räumen jung entgegen senden,\r\nDes Lebens Ruf an uns wird niemals enden,\r\nWohlan denn, Herz, nimm Abschied und gesunde!";

                // SENDER performs sealing
                var sealedData  = new SAFESealSealer().Seal(rsa2048_PrivateKey,
                                                            Encoding.UTF8.GetBytes(plaintext1));

                Assert.IsTrue(sealedData.HasNoErrors);


                // RECIPIENT performs revealing
                var plaintext2  = new SAFESealRevealer().Reveal(rsa2048_PublicKey,
                                                                sealedData);

                Assert.IsTrue  (plaintext2.HasNoErrors);
                Assert.AreEqual(plaintext1, Encoding.UTF8.GetString(plaintext2));

            }

        }

        #endregion


        #region RSA4096_Seal_ShortMessage_Test()

        [Test]
        public void RSA4096_Seal_ShortMessage_Test()
        {

            Assert.IsNotNull(rsa4096_KeyPair);
            Assert.IsNotNull(rsa4096_PrivateKey);
            Assert.IsNotNull(rsa4096_PublicKey);

            if (rsa4096_KeyPair    is not null &&
                rsa4096_PrivateKey is not null &&
                rsa4096_PublicKey  is not null)
            {

                var plaintext1  = "S.A.F.E. e.V.";

                // SENDER performs sealing
                var sealedData  = new SAFESealSealer().Seal(rsa4096_PrivateKey,
                                                            Encoding.UTF8.GetBytes(plaintext1));

                Assert.IsTrue(sealedData.HasNoErrors);


                // RECIPIENT performs revealing
                var plaintext2  = new SAFESealRevealer().Reveal(rsa4096_PublicKey,
                                                                sealedData);

                Assert.IsTrue  (plaintext2.HasNoErrors);
                Assert.AreEqual(plaintext1, Encoding.UTF8.GetString(plaintext2));

            }

        }

        #endregion

        //ToDo(ahzf): Long messages seem to be broken!
        #region RSA4096_Seal_LongMessage_Test()

        [Test]
        public void RSA4096_Seal_LongMessage_Test()
        {

            Assert.IsNotNull(rsa4096_KeyPair);
            Assert.IsNotNull(rsa4096_PrivateKey);
            Assert.IsNotNull(rsa4096_PublicKey);

            if (rsa4096_KeyPair    is not null &&
                rsa4096_PrivateKey is not null &&
                rsa4096_PublicKey  is not null)
            {

                var plaintext1  = "Stufen\r\nWie jede Blüte welkt und jede Jugend\r\nDem Alter weicht, blüht jede Lebensstufe,\r\nBlüht jede Weisheit auch und jede Tugend\r\nZu ihrer Zeit und darf nicht ewig dauern.\r\nEs muß das Herz bei jedem Lebensrufe\r\nBereit zum Abschied sein und Neubeginne,\r\nUm sich in Tapferkeit und ohne Trauern\r\nIn andre, neue Bindungen zu geben.\r\nUnd jedem Anfang wohnt ein Zauber inne,\r\nDer uns beschützt und der uns hilft, zu leben.\r\n\r\nWir sollen heiter Raum um Raum durchschreiten,\r\nAn keinem wie an einer Heimat hängen,\r\nDer Weltgeist will nicht fesseln uns und engen,\r\nEr will uns Stuf´ um Stufe heben, weiten.\r\nKaum sind wir heimisch einem Lebenskreise\r\nUnd traulich eingewohnt, so droht Erschlaffen;\r\nNur wer bereit zu Aufbruch ist und Reise,\r\nMag lähmender Gewöhnung sich entraffen.\r\n\r\nEs wird vielleicht auch noch die Todesstunde\r\nUns neuen Räumen jung entgegen senden,\r\nDes Lebens Ruf an uns wird niemals enden,\r\nWohlan denn, Herz, nimm Abschied und gesunde!";

                // SENDER performs sealing
                var sealedData  = new SAFESealSealer().Seal(rsa4096_PrivateKey,
                                                            Encoding.UTF8.GetBytes(plaintext1));

                Assert.IsTrue(sealedData.HasNoErrors);


                // RECIPIENT performs revealing
                var plaintext2  = new SAFESealRevealer().Reveal(rsa4096_PublicKey,
                                                                sealedData);

                Assert.IsTrue  (plaintext2.HasNoErrors);
                Assert.AreEqual(plaintext1, Encoding.UTF8.GetString(plaintext2));

            }

        }

        #endregion


    }

}
