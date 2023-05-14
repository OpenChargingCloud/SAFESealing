

#region Usings

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing
{
    /// <summary>
    /// A RSA public key.
    /// </summary>
    public class RSAPublicKey
    {

        #region Properties

        /// <summary>
        /// The RSA public key.
        /// </summary>
        public RsaKeyParameters Key;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new RSA public key.
        /// </summary>
        /// <param name="Key">A RSA public key.</param>
        public RSAPublicKey(RsaKeyParameters Key)
        {

            if (Key.IsPrivate)
                throw new ArgumentException("The given RSA key ist not a RSA public key!", nameof(Key));

            this.Key = Key;

        }

        #endregion


        #region (static, implicit) RSAPublicKey(RSAKeyPair)

        /// <summary>
        /// Convert the given RSA key pair into a RSA public key.
        /// </summary>
        /// <param name="RSAKeyPair">A RSA key pair.</param>
        public static implicit operator RSAPublicKey(AsymmetricCipherKeyPair RSAKeyPair)
        {

            if (RSAKeyPair?.Public is null || RSAKeyPair.Public is not RsaKeyParameters publicKey)
                throw new ArgumentException("The given key pair does not contain a RSA public key.", nameof(RSAKeyPair));

            return new RSAPublicKey(publicKey);

        }

        #endregion

    }

}
