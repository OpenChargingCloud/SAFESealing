using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SAFESealing
{
    public interface ICryptoFactory
    {

        /**
         * <p>getCipherFromCipherSpec.</p>
         *
         * @param algorithmSpec a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object
         * @return a {@link javax.crypto.Cipher} object
         * @throws javax.crypto.NoSuchPaddingException if any.
         * @throws java.security.NoSuchAlgorithmException if any.
         * @throws java.security.NoSuchProviderException if any.
         */
        Cipher GetCipherFromCipherSpec(AlgorithmSpec algorithmSpec);

        /**
         * <p>getEllipticCurve.</p>
         *
         * @param algorithmSpec a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object
         * @return a {@link org.bouncycastle.crypto.params.ECDomainParameters} object
         */
        ECDomainParameters GetEllipticCurve(AlgorithmSpec algorithmSpec);

    }
}
