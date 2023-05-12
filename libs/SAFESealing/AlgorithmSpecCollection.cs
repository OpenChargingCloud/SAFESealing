using Org.BouncyCastle.Asn1;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SAFESealing
{
    public class AlgorithmSpecCollection
    {

        private static readonly Dictionary<DerObjectIdentifier, AlgorithmSpec> algorithms = new();

        public static IEnumerable<AlgorithmSpec> GetAllDefined()
            => algorithms.Values;

        public static AlgorithmSpec LookupByOID(DerObjectIdentifier oid)
            => algorithms[oid];

        static AlgorithmSpecCollection()
        {

            algorithms.Add(SharedConstants.OID_AES_256_ECB,                AES256ECB);
            algorithms.Add(SharedConstants.OID_AES_256_CBC,                AES256CBC);
            algorithms.Add(SharedConstants.OID_IIP_ALGORITHM,              IIP);
            algorithms.Add(SharedConstants.OID_RSA_ECB,                    RSA2048);
            algorithms.Add(SharedConstants.OID_COMPRESSION_NONE,           COMPRESSION_NONE);
            algorithms.Add(SharedConstants.OID_COMPRESSION_GZIP,           COMPRESSION_GZIP);
            algorithms.Add(SharedConstants.OID_ECDH_ALGORITHM,             ECDH);

            // all supported algorithms must be specified here, lest they fail parse/validation.
            algorithms.Add(SharedConstants.OID_EC_NAMED_CURVE_SECP256R1,   ECSECP256R1);
            algorithms.Add(SharedConstants.OID_SHA256,                     SHA256);

        }



        /** Constant <code>ECDH</code> */
        public static readonly AlgorithmSpec ECDH                = new (SharedConstants.OID_ECDH_ALGORITHM,              "ECDH",                 AlgorithmSpec.CryptoTypes.KEY_AGREEMENT);
        /** Constant <code>ECSECP256R1</code> */
        public static readonly AlgorithmSpec ECSECP256R1         = new (SharedConstants.OID_EC_NAMED_CURVE_SECP256R1,    "secp256r1",            AlgorithmSpec.CryptoTypes.ELLIPTIC_CURVE, true, 0, 0, 0); // EC @TODO additional parmeters?
        /** Constant <code>SHA256</code> */
        public static readonly AlgorithmSpec SHA256              = new (SharedConstants.OID_SHA256,                      "SHA-256",              AlgorithmSpec.CryptoTypes.DIGEST);
        /** Constant <code>COMPRESSION_NONE</code> */
        public static readonly AlgorithmSpec COMPRESSION_NONE    = new (SharedConstants.OID_COMPRESSION_NONE,            "no compression",       AlgorithmSpec.CryptoTypes.COMPRESSION);

        /** Constant <code>COMPRESSION_GZIP</code> */
        public static readonly AlgorithmSpec COMPRESSION_GZIP    = new (SharedConstants.OID_COMPRESSION_GZIP,            "gzip",                 AlgorithmSpec.CryptoTypes.COMPRESSION);

        /** Constant <code>AES256ECB</code> means AES/ECB/NoPadding*/
        public static readonly AlgorithmSpec AES256ECB           = new (SharedConstants.OID_AES_256_ECB,                 "AES/ECB",              AlgorithmSpec.CryptoTypes.CIPHER, false, 256, 16, 16);
        /** Constant <code>AES256CBC</code> */
        public static readonly AlgorithmSpec AES256CBC           = new (SharedConstants.OID_AES_256_CBC,                 "AES/CBC",              AlgorithmSpec.CryptoTypes.CIPHER, false, 256, 16, 16);
        /** Constant <code>IIP</code> */
        public static readonly AlgorithmSpec IIP                 = new (SharedConstants.OID_IIP_ALGORITHM,               "IIP",                  AlgorithmSpec.CryptoTypes.PADDING);
        /** Constant <code>RSA2048</code> */
        public static readonly AlgorithmSpec RSA2048             = new (SharedConstants.OID_RSA_ECB,                     "RSA/ECB/NoPadding",    AlgorithmSpec.CryptoTypes.CIPHER, true, 2048, 256, 1);
        /** Constant <code>RSA4096</code> */
        public static readonly AlgorithmSpec RSA4096             = new (SharedConstants.OID_RSA_ECB,                     "RSA/ECB/NoPadding",    AlgorithmSpec.CryptoTypes.CIPHER, true, 4096, 512, 1);

        /** Constant <code>RSA2048_on_SunJCE</code> */
        public static readonly AlgorithmSpec RSA2048_on_SunJCE   = new (SharedConstants.OID_RSA_ECB,                     "RSA/ECB/NoPadding",    AlgorithmSpec.CryptoTypes.CIPHER, true, 2048, 256, 0); // internal test constructor, not public





    }

}
