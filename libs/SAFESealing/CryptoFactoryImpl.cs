using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SAFESealing
{
    public class CryptoFactoryImpl
    {


        public IAsymmetricBlockCipher? GetCipherFromCipherSpec(AlgorithmSpec algorithmSpec)
        {

            switch (algorithmSpec.CryptoType)
            {

                case AlgorithmSpec.CryptoTypes.CIPHER:
                case AlgorithmSpec.CryptoTypes.DIGEST:
                    // we need special handling for RSA/ECB/NoPadding
                    if (algorithmSpec.OID.Id.Equals(SharedConstants.OID_RSA_ECB.Id))
                        return GetRSAECB(algorithmSpec);

                    // 1.3.132.1.12   for KEY_AGREEMENT

                    // regular case

                    //ahzf: C# does not support this!!!
                    //var cipher = Cipher.getInstance(algorithmSpec.getOID().getId(), securityProvider);
                    //return cipher;
                    return null;

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
        private IAsymmetricBlockCipher GetRSAECB(AlgorithmSpec algorithmSpec)
            => new RsaEngine(); // corresponds to "RSA/ECB/NoPadding"

    }

}
