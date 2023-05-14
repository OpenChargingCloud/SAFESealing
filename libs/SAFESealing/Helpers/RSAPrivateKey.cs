
#region Usings

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// A RSA private key.
    /// </summary>
    public class RSAPrivateKey
    {

        #region Properties

        /// <summary>
        /// The RSA private key.
        /// </summary>
        public RsaPrivateCrtKeyParameters Key;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new RSA private key.
        /// </summary>
        /// <param name="Key">A RSA private key.</param>
        public RSAPrivateKey(RsaPrivateCrtKeyParameters Key)
        {

            if (!Key.IsPrivate)
                throw new ArgumentException("The given RSA key ist not a RSA private key!", nameof(Key));

            this.Key = Key;

        }

        #endregion


        #region (static, implicit) RSAPrivateKey(RSAKeyPair)

        /// <summary>
        /// Convert the given RSA key pair into a RSA private key.
        /// </summary>
        /// <param name="RSAKeyPair">A RSA key pair.</param>
        public static implicit operator RSAPrivateKey(AsymmetricCipherKeyPair RSAKeyPair)
        {

            if (RSAKeyPair?.Private is null || RSAKeyPair.Private is not RsaPrivateCrtKeyParameters privateKey)
                throw new ArgumentException("The given key pair does not contain a RSA private key.", nameof(RSAKeyPair));

            return new RSAPrivateKey(privateKey);

        }

        #endregion

    }

}
