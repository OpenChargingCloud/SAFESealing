﻿
#region Usings

using System.Diagnostics;

using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// Verify and extract sealed OCMF message according to SAFE e.V. specifications.
    /// </summary>
    public class SAFESealRevealer
    {

        #region Properties

        /// <summary>
        /// Flag shorthand for NONE (==RSA+IIP) or ECDHE.
        /// Later versions may use an enum.
        /// </summary>
        public CryptoVariant  KeyAgreementMode    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new SAFE seal revealer to verify and extract sealed messages.
        /// </summary>
        /// <param name="KeyAgreementMode">Whether to use ECDHE+AES or RSA cryptography.</param>
        public SAFESealRevealer(CryptoVariant KeyAgreementMode = CryptoVariant.ECDHE_AES)
        {

            this.KeyAgreementMode  = KeyAgreementMode;

        }

        #endregion


        #region Reveal(SenderPublicKey,    RecipientPrivateKey,    SealedMessage)

        /// <summary>
        /// Verify and reveal a sealed message.
        /// </summary>
        /// <param name="SenderPublicKey">An elliptic curve public key of the sender.</param>
        /// <param name="RecipientPrivateKey">An elliptic curve private key of a recipient.</param>
        /// <param name="SealedMessage">A sealed message.</param>
        /// <returns>The verified cleartext.</returns>
        public Byte[] Reveal(ECPublicKeyParameters   SenderPublicKey,
                             ECPrivateKeyParameters  RecipientPrivateKey,
                             Byte[]                  SealedMessage)
        {
            try
            {

                return new SAFE_EllipticCurve_Seal().
                           Reveal(SealedMessage,
                                  RecipientPrivateKey,
                                  SenderPublicKey);

            }
            catch (Exception e)
            {
                // Hiding the specific exception to prevent "padding oracle" type attacks, and simplify usage.
                Debug.WriteLine(e);
            }

            return Array.Empty<Byte>();

        }

        #endregion

        //ToDo: Add RSA!

        #region Reveal(RawSenderPublicKey, RawRecipientPrivateKey, SealedMessage)

        /// <summary>
        /// Verify and reveal a sealed message.
        /// </summary>
        /// <param name="RawSenderPublicKey">A RAW public key of a sender as an array of bytes.</param>
        /// <param name="RawRecipientPrivateKey">A RAW private key of a recipient as an array of bytes.</param>
        /// <param name="SealedMessage">A sealed message.</param>
        /// <returns>The verified cleartext.</returns>
        public Byte[] Reveal(Byte[] RawSenderPublicKey,
                             Byte[] RawRecipientPrivateKey,
                             Byte[] SealedMessage)
        {
            // todo perform deterministic conversion from bytearrays to keys.
            // then call the "real" function
            return Array.Empty<Byte>();
        }

        #endregion


    }

}
