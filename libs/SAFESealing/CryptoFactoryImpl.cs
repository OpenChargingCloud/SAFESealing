﻿using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace SAFESealing
{
    public class CryptoFactoryImpl : ICryptoFactory
    {


        public Cipher? GetCipherFromCipherSpec(AlgorithmSpec AlgorithmSpec)
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

                    var aes = Aes.Create();
                    aes.Mode    = System.Security.Cryptography.CipherMode.ECB;
                    aes.Padding = PaddingMode.None;

                    return new Cipher(aes);

            }

            return null;

        }

        public ECDomainParameters? GetEllipticCurve(AlgorithmSpec algorithmSpec)
        {

            if (algorithmSpec.CryptoType != AlgorithmSpec.CryptoTypes.ELLIPTIC_CURVE)
                throw new Exception("wrong type");

            var curveName  = algorithmSpec.Name;

            var curve      = curveName?.Contains("brain") == true
                                 ? TeleTrusTNamedCurves.GetByName(curveName)
                                 : SecNamedCurves.      GetByName(curveName);

            return new ECDomainParameters(curve.Curve,
                                          curve.G,
                                          curve.N,
                                          curve.H);

        }



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
        private Cipher GetRSAECB(AlgorithmSpec algorithmSpec)
            => new (new RsaEngine()); // corresponds to "RSA/ECB/NoPadding"

    }

}
