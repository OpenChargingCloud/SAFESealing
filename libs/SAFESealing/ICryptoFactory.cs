using Org.BouncyCastle.Crypto.Parameters;

namespace SAFESealing
{
    public interface ICryptoFactory
    {

        /// <summary>
        /// Get cipher from cipher spec.
        /// </summary>
        /// <param name="AlgorithmSpec">a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object.</param>
        /// <returns>a {@link javax.crypto.Cipher} object</returns>
        Cipher              GetCipherFromCipherSpec(AlgorithmSpec AlgorithmSpec);

        /// <summary>
        /// Get elliptic curve.
        /// </summary>
        /// <param name="AlgorithmSpec">a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object.</param>
        /// <returns>a {@link org.bouncycastle.crypto.params.ECDomainParameters} object</returns>
        ECDomainParameters  GetEllipticCurve       (AlgorithmSpec AlgorithmSpec);

    }
}
