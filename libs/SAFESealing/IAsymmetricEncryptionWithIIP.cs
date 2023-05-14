
#region Usings

using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing
{

    public interface IAsymmetricEncryptionWithIIP
    {

        /// <summary>
        /// Return the symmetric IV.
        /// </summary>
        Byte[] SymmetricIV { get; }


        /// <summary>
        /// Pad encrypt and package.
        /// </summary>
        /// <param name="Data">An array of {@link byte} objects</param>
        /// <param name="OtherSideECPublicKey">a {@link java.security.PublicKey} object</param>
        /// <param name="OurECPrivateKey">a {@link java.security.PrivateKey} object</param>
        /// <param name="KeyDiversification">an array of {@link byte} objects</param>
        /// <returns>an array of {@link byte} objects</returns>
        Byte[] PadEncryptAndPackage(Byte[]                  Data,
                                    ECPublicKeyParameters   OtherSideECPublicKey,
                                    ECPrivateKeyParameters  OurECPrivateKey,
                                    Byte[]                  KeyDiversification);


        /// <summary>
        /// Pad encrypt and package for multiple recipients.
        /// </summary>
        /// <param name="ContentToSeal">an array of {@link byte} objects</param>
        /// <param name="RecipientKeys">an array of {@link java.security.PublicKey} objects</param>
        /// <param name="SenderKey">a {@link java.security.PrivateKey} object</param>
        /// <param name="KseyDiversificationForEC">an array of {@link byte} objects</param>
        /// <returns>an array of {@link byte} objects</returns>
        Byte[] PadEncryptAndPackage(Byte[]                              ContentToSeal,
                                    IEnumerable<ECPublicKeyParameters>  RecipientKeys,
                                    ECPrivateKeyParameters              SenderKey,
                                    Byte[]                              KseyDiversificationForEC);


        /// <summary>
        /// Decrypt and verify.
        /// </summary>
        /// <param name="EncryptedData">an array of {@link byte} objects</param>
        /// <param name="OtherSideECPublicKey">a {@link java.security.PublicKey} object</param>
        /// <param name="OurECPrivateKey">a {@link java.security.PrivateKey} object</param>
        /// <param name="KeyDiversificationForEC">an array of {@link byte} objects</param>
        /// <param name="IVForSymmetricCrypto">an array of {@link byte} objects</param>
        /// <returns>an array of {@link byte} objects</returns>
        Byte[] DecryptAndVerify(Byte[]                  EncryptedData,
                                ECPublicKeyParameters   OtherSideECPublicKey,
                                ECPrivateKeyParameters  OurECPrivateKey,
                                Byte[]                  KeyDiversificationForEC,
                                Byte[]                  IVForSymmetricCrypto);


    }

}
