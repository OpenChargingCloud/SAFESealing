using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Gnu;
using Org.BouncyCastle.Asn1.Kisa;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.Pkcs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SAFESealing
{
    public static class SharedConstants
    {


        public static readonly Int32                SAFE_SEAL_VERSION = 1;

        public static readonly DerObjectIdentifier  OID_SAFE_SEAL      = new ("1.3.6.1.4.1.60279.1.1");

        public static readonly DerObjectIdentifier  OID_SAFE_SEAL_AUTH = new ("1.3.6.1.4.1.60279.1.2");

        /// <summary>
        /// See https://www.rfc-editor.org/rfc/rfc8017.html A.1
        /// </summary>
        public static readonly DerObjectIdentifier  OID_RSA_ECB        = new ("1.2.840.113549.1.1.1"); // issues with BouncyCastle vs. Oracle JCE


        static SharedConstants()
        {

            keyExchange.Add(OID_ECDH_ALGORITHM, "ECDH"); // see RFC 6637; and RFC 5480 clause 2.1.2
            // keyExchange.put(OIWObjectIdentifiers.elGamalAlgorithm, "ELGAMAL"); -- not valid yet, possible future extension

            keyDiversificationAlgorithms.Add(NistObjectIdentifiers.IdSha224, "SHA224");
            keyDiversificationAlgorithms.Add(NistObjectIdentifiers.IdSha256, "SHA256");
            keyDiversificationAlgorithms.Add(NistObjectIdentifiers.IdSha384, "SHA384");
            keyDiversificationAlgorithms.Add(NistObjectIdentifiers.IdSha512, "SHA512");
            keyDiversificationAlgorithms.Add(NistObjectIdentifiers.IdSha3_224, "SHA3-224");
            keyDiversificationAlgorithms.Add(NistObjectIdentifiers.IdSha3_256, "SHA3-256");
            keyDiversificationAlgorithms.Add(NistObjectIdentifiers.IdSha3_384, "SHA3-384");
            keyDiversificationAlgorithms.Add(NistObjectIdentifiers.IdSha3_512, "SHA3-512");


            ciphers.Add(NistObjectIdentifiers.IdAes256Cbc, "AES-256/CBC");
            ciphers.Add(NistObjectIdentifiers.IdAes256Ecb, "AES-256/ECB");
            ciphers.Add(NistObjectIdentifiers.IdAes128Ecb, "AES-128/ECB");
            ciphers.Add(NistObjectIdentifiers.IdAes192Ecb, "AES-192/ECB");
            ciphers.Add(NistObjectIdentifiers.IdAes128Cbc, "AES-128/CBC");
            ciphers.Add(NistObjectIdentifiers.IdAes192Cbc, "AES-192/CBC");

            // this has been tested, works in crypto, but not in current implementation - yet
            futureCiphers.Add(PkcsObjectIdentifiers.RsaEncryption, "RSA");

            // these have not been tested yet
            futureCiphers.Add(NttObjectIdentifiers. IdCamellia128Cbc, "CAMELLIA-128/CBC");
            futureCiphers.Add(NttObjectIdentifiers. IdCamellia192Cbc, "CAMELLIA-192/CBC");
            futureCiphers.Add(NttObjectIdentifiers. IdCamellia256Cbc, "CAMELLIA-256/CBC");
            futureCiphers.Add(KisaObjectIdentifiers.IdSeedCbc, "SEED/CBC");
            futureCiphers.Add(MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC, "IDEA/CBC");
            futureCiphers.Add(MiscObjectIdentifiers.cast5CBC, "CAST5/CBC");
            futureCiphers.Add(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_ECB, "Blowfish/ECB");
            futureCiphers.Add(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC, "Blowfish/CBC");
            futureCiphers.Add(GnuObjectIdentifiers. Serpent128Ecb, "Serpent-128/ECB");
            futureCiphers.Add(GnuObjectIdentifiers. Serpent128Cbc, "Serpent-128/CBC");
            futureCiphers.Add(GnuObjectIdentifiers. Serpent192Ecb, "Serpent-192/ECB");
            futureCiphers.Add(GnuObjectIdentifiers. Serpent192Cbc, "Serpent-192/CBC");
            futureCiphers.Add(GnuObjectIdentifiers. Serpent256Ecb, "Serpent-256/ECB");
            futureCiphers.Add(GnuObjectIdentifiers. Serpent256Cbc, "Serpent-256/CBC");

            paddings.Add(OID_IIP_ALGORITHM, "IIP");


            // how can we be sure java manages to initialise this in the right order?
            // since OID are guaranteed to be globally unique, no collision can occur here.
            foreach (var _keyExchange in keyExchange)
                combinedForwardMap.Add(_keyExchange.Key, _keyExchange.Value);

            foreach (var _keyExchangeAlgorithm in keyExchangeAlgorithms)
                combinedForwardMap.Add(_keyExchangeAlgorithm.Key, _keyExchangeAlgorithm.Value);

            foreach (var _keyDiversificationAlgorithm in keyDiversificationAlgorithms)
                combinedForwardMap.Add(_keyDiversificationAlgorithm.Key, _keyDiversificationAlgorithm.Value);

            foreach (var _cipher in ciphers)
                combinedForwardMap.Add(_cipher.Key, _cipher.Value);

            // combinedForwardMap.putAll(futureCiphers); -- during development/testing only

            foreach (var _padding in paddings)
                combinedForwardMap.Add(_padding.Key, _padding.Value);

            // constructing the reverse map could, theorhetically, cause collisions; above limited data set should not generate any.
            foreach (var reversed in combinedForwardMap)
                combinedReverseMap.Add(reversed.Value, reversed.Key);

        }

        /**
         * Algorithm name lookup from OID.
         * This is not a generic function, its scope is limited to this software.
         *
         * @param oid OID to look up
         * @return name/algorithm spec belonging to the OID
         * @throws java.security.NoSuchAlgorithmException if this class could not find the OID provided
         */
        public static String GetNameForOID(DerObjectIdentifier oid)
        {

            if (combinedForwardMap.TryGetValue(oid, out var oidValue))
                return oidValue;

            throw new Exception(oid.Id);

        }

        /**
         * reverse lookup from name to OID. Note this is not checking for aliases;
         * you may have provided a String that would be perfectly understandable for a human,
         * but fails in this automated lookup.
         *
         * @param algorithmName the name or algorithm spec to look up
         * @return corresponding OID
         * @throws java.security.NoSuchAlgorithmException if this specific lookup could not find a match
         */
        public static DerObjectIdentifier GetOIDForName(String algorithmName)
        {

            if (combinedReverseMap.TryGetValue(algorithmName, out var derObjectIdentifier))
                return derObjectIdentifier;

            throw new Exception(algorithmName);

        }


        /// <summary>
        /// accessors for automated tests
        /// </summary>
        public static IEnumerable<DerObjectIdentifier> CiphersOIDs
            => ciphers.Keys;

        public static IEnumerable<DerObjectIdentifier> KeyDiversificationOIDs
            => keyDiversificationAlgorithms.Keys;

        public static IEnumerable<DerObjectIdentifier> KeyExchangeAlgorithmsOIDs
            => keyExchangeAlgorithms.Keys;


        //--------------------------------------------------------------------------------------------------------------------
        // we got a bunch of possible EC curves.

        /** Constant <code>OID_EL_GAMAL</code> */
        public static readonly DerObjectIdentifier OID_EL_GAMAL                     = new ("1.3.6.1.4.1.3029.1.2");
        /** Constant <code>OID_ECDH_PUBLIC_KEY</code> */
        public static readonly DerObjectIdentifier OID_ECDH_PUBLIC_KEY              = new ("1.2.840.10045.2.1");
        // our SAFE eV default as of 2023 is secp256r1

        /*
        the recommended curves are:
              secp256r1 	1.2.840.10045.3.1.7 	NIST P-256, X9.62 prime256v1
              secp384r1 	1.3.132.0.34 	NIST P-384
              secp521r1 	1.3.132.0.35 	NIST P-521
         */

        /** Constant <code>OID_EC_NAMED_CURVE_SECP256R1</code> */
        public static readonly DerObjectIdentifier OID_EC_NAMED_CURVE_SECP256R1     = new ("1.2.840.10045.3.1.7");
        /** Constant <code>OID_EC_NAMED_CURVE_SECP192R1</code> */
        public static readonly DerObjectIdentifier OID_EC_NAMED_CURVE_SECP192R1     = new ("1.2.840.10045.3.1.1");
        /** Constant <code>OID_EC_NAMED_CURVE_X25519</code> */
        public static readonly DerObjectIdentifier OID_EC_NAMED_CURVE_X25519        = new ("1.3.6.1.4.1.3029.1.5.1"); // "curvey25519""

        /** Constant <code>OID_COMPRESSION_NONE</code> */
        public static readonly DerObjectIdentifier OID_COMPRESSION_NONE             = new ("1.3.6.1.4.1.21876.1.1.1.1.0");
        /** Constant <code>OID_COMPRESSION_DEFLATE</code> */
        public static readonly DerObjectIdentifier OID_COMPRESSION_DEFLATE          = new ("1.3.6.1.4.1.21876.1.1.1.1.1");
        /** Constant <code>OID_COMPRESSION_GZIP</code> */
        public static readonly DerObjectIdentifier OID_COMPRESSION_GZIP             = new ("1.3.6.1.4.1.21876.1.1.1.1.2");
        /** Constant <code>OID_COMPRESSION_BROTLI</code> */
        public static readonly DerObjectIdentifier OID_COMPRESSION_BROTLI           = new ("1.3.6.1.4.1.21876.1.1.1.1.3");

        // oracle provided, see oracle.security.crypto.cms
        static readonly DerObjectIdentifier oracle_id_ct_compressedData             = new ("1.2.840.113549.1.9.16.1.9");
        static readonly DerObjectIdentifier oraclie_id_alg_zlibCompress             = new ("1.2.840.113549.1.3.86.2.14");


        /** Constant <code>OID_AES_128_ECB</code> */
        public static readonly DerObjectIdentifier OID_AES_128_ECB                  = new ("2.16.840.1.101.3.4.1.1");
        /** Constant <code>OID_AES_128_CBC</code> */
        public static readonly DerObjectIdentifier OID_AES_128_CBC                  = new ("2.16.840.1.101.3.4.1.2");
        /** Constant <code>OID_AES_192_ECB</code> */
        public static readonly DerObjectIdentifier OID_AES_192_ECB                  = new ("2.16.840.1.101.3.4.1.21");
        /** Constant <code>OID_AES_192_CBC</code> */
        public static readonly DerObjectIdentifier OID_AES_192_CBC                  = new ("2.16.840.1.101.3.4.1.22");

        /** Constant <code>OID_AES_256_ECB</code> */
        public static readonly DerObjectIdentifier OID_AES_256_ECB                  = new ("2.16.840.1.101.3.4.1.41");
        /** Constant <code>OID_AES_256_CBC</code> */
        public static readonly DerObjectIdentifier OID_AES_256_CBC                  = new ("2.16.840.1.101.3.4.1.42");

        // ---- used for key derivation only ----
        // RFC8017:   id-sha512    OBJECT IDENTIFIER ::= { joint-iso-itu-t (2) country (16) us (840) organization (1) gov (101) csor (3) nistalgorithm (4) hashalgs (2) 3 }
        /** Constant <code>OID_SHA_512</code> */
        public static readonly DerObjectIdentifier OID_SHA_512                      = new ("1.2.840.1.101.3.4.2.3");

        //RFC8017:  id-sha256    OBJECT IDENTIFIER ::= { joint-iso-itu-t (2) country (16) us (840) organization (1) gov (101) csor (3) nistalgorithm (4) hashalgs (2) 1 }
        /** Constant <code>OID_SHA256</code> */
        public static readonly DerObjectIdentifier OID_SHA256                       = new ("2.16.840.1.101.3.4.2.1");

        // source: https://oidref.com/2.16.840.1.101.3.4.2 NIST Algorithm IDs
        /** Constant <code>OID_SHA512</code> */
        public static readonly DerObjectIdentifier OID_SHA512                       = new ("2.16.840.1.101.3.4.2.3");
        /** Constant <code>OID_SHA512_256</code> */
        public static readonly DerObjectIdentifier OID_SHA512_256                   = new ("2.16.840.1.101.3.4.2.6");
        /** Constant <code>OID_SHA3_256</code> */
        public static readonly DerObjectIdentifier OID_SHA3_256                     = new ("2.16.840.1.101.3.4.2.8");
        /** Constant <code>OID_SHA3_512</code> */
        public static readonly DerObjectIdentifier OID_SHA3_512                     = new ("2.16.840.1.101.3.4.2.10");


        // supported OIDs, maintenance here.
        /** Constant <code>OID_ECDH_ALGORITHM</code> */
        public static readonly DerObjectIdentifier OID_ECDH_ALGORITHM               = new ("1.3.132.1.12");
        // ECDSA and ECDH use the same OID; as per RFC 3279 2.3.5
        // placed under the ANSI X9 62 branch  at 1.2.840.10045
        /** Constant <code>OID_EC_PUBLIC_KEY_TYPE</code> */
        public static readonly DerObjectIdentifier OID_EC_PUBLIC_KEY_TYPE           = new ("1.2.840.10045.62.2");
        /** Constant <code>OID_EC_PUBLIC_KEY</code> */
        public static readonly DerObjectIdentifier OID_EC_PUBLIC_KEY                = new ("1.2.840.10045.62.2.1");

        /** Constant <code>OID_EC_UNRESTRICTED</code> */
        public static readonly DerObjectIdentifier OID_EC_UNRESTRICTED              = new ("1.2.840.10045.2.1");


        //--------------------------------------------------------------------------------------------------------------------

        // NB: we are not using any algorithm for HMAC purposes; these are used for key diversification at key exchange level only.
        private static readonly Dictionary<DerObjectIdentifier, String> keyDiversificationAlgorithms  = new ();
        private static readonly Dictionary<DerObjectIdentifier, String> keyExchange                   = new ();
        private static readonly Dictionary<DerObjectIdentifier, String> keyExchangeAlgorithms         = new ();
        private static readonly Dictionary<DerObjectIdentifier, String> ciphers                       = new ();
        private static readonly Dictionary<DerObjectIdentifier, String> futureCiphers                 = new ();
        private static readonly Dictionary<DerObjectIdentifier, String> paddings                      = new ();
        private static readonly Dictionary<DerObjectIdentifier, String> combinedForwardMap            = new ();
        private static readonly Dictionary<String, DerObjectIdentifier> combinedReverseMap            = new ();





        /** Constant <code>OID_IIP_ALGORITHM</code> */
        public static readonly DerObjectIdentifier OID_IIP_ALGORITHM = new ("1.3.6.1.4.1.21876.4.3.1");



    }

}
