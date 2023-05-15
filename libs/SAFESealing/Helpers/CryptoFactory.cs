
#region Usings

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace SAFESealing
{

    public static class CryptoFactory
    {

        #region (static) GetCipherFromCipherSpec(AlgorithmSpec)

        public static Cipher? GetCipherFromCipherSpec(AlgorithmSpec AlgorithmSpec)
        {

            switch (AlgorithmSpec.CryptoType)
            {

                case AlgorithmSpec.CryptoTypes.CIPHER:
                case AlgorithmSpec.CryptoTypes.DIGEST:
                    // we need special handling for RSA/ECB/NoPadding
                    if (AlgorithmSpec.OID.Id.Equals(SharedConstants.OID_RSA_ECB.Id))
                        return GetRSAECB(AlgorithmSpec);

                    // 1.3.132.1.12   for KEY_AGREEMENT

                    // regular case
                    //var cipher = Cipher.getInstance(algorithmSpec.getOID().getId(), securityProvider);


                    //var aes = Aes.Create();
                    //aes.Mode    = System.Security.Cryptography.CipherMode.ECB;
                    //aes.Padding = PaddingMode.None;

                    //return Cipher.AES_ECB();
                    return null;

            }

            return null;

        }

        #endregion

        #region (static) GetEllipticCurve(AlgorithmSpec)

        public static ECDomainParameters? GetEllipticCurve(AlgorithmSpec AlgorithmSpec)
        {

            if (AlgorithmSpec.CryptoType != AlgorithmSpec.CryptoTypes.ELLIPTIC_CURVE)
                throw new Exception("wrong type");

            var curveName  = AlgorithmSpec.Name;

            var curve      = curveName?.Contains("brain") == true
                                 ? TeleTrusTNamedCurves.GetByName(curveName)
                                 : SecNamedCurves.      GetByName(curveName);

            return new ECDomainParameters(curve.Curve,
                                          curve.G,
                                          curve.N,
                                          curve.H);

        }

        #endregion

        #region (static) GetRSAECB(AlgorithmSpec)

        /**
         * workaround for differences in crypto providers.
         * BouncyCastle reduces the usable part of the RSA block by a full byte;
         * SunJCE does not (but the MSB of the block still isn't usable).
         * The practical effect of this difference is found in the blocksizes, though -
         * which are of high importance to padding.
         * <p>
         * Additional workaround for BC behaviour not returning regular "plain RSA"
         * for the specification-compliant OID, but some other RSA variant instead.
         *
         * @param algorithmSpec algorithm spec provided.
         * @return
         */
        private static Cipher GetRSAECB(AlgorithmSpec AlgorithmSpec)

            => new (new RsaEngine()); // corresponds to "RSA/ECB/NoPadding"

        #endregion

    }

}
