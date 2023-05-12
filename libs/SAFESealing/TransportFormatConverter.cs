using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Utilities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SAFESealing
{
    public class TransportFormatConverter
    {

        private DerObjectIdentifier?  keyAgreementProtocolOID;
        private DerObjectIdentifier?  ecAlgorithmOID;
        private DerObjectIdentifier?  keyDiversificationOID;
        private DerObjectIdentifier?  encryptionOID;
        private DerObjectIdentifier?  compressionOID;
        private Asn1Encodable         keyReference; // or Asn1EncodableVector, depending


        public TransportFormatConverter()
        { }

        /**
         * <p>wrapForTransport.</p>
         *
         * @param ids a {@link com.metabit.custom.safe.safeseal.impl.InternalTransportTuple} object
         * @return an array of {@link byte} objects
         * @throws java.io.IOException if any.s
         */
        public Byte[] WrapForTransport(InternalTransportTuple ids)
        {

            keyAgreementProtocolOID  = ids.CryptoSettings.KeyAgreementProtocol?.       OID;
            ecAlgorithmOID           = ids.CryptoSettings.KeyAgreementCipher?.         OID;
            keyDiversificationOID    = ids.CryptoSettings.KeyDiversificationAlgorithm?.OID;
            encryptionOID            = ids.CryptoSettings.Encryption?.                 OID;
            compressionOID           = ids.CryptoSettings.Compression?.                OID;

            Asn1EncodableVector ecDetails = null; // details about the elliptic curve used, optional. not in current version.
            // see https://www.rfc-editor.org/rfc/rfc3279 for encoding of ECParameters

            keyReference = null; // key reference for the public key to be used. not in current version

            // using bouncy castle. easier with TLVIterator in a later version
            //----
            // prepare first part
            var encryptionPart = new Asn1EncodableVector();
            encryptionPart.Add(SharedConstants.OID_IIP_ALGORITHM); // or wrap in context[1] ?
            encryptionPart.Add(new DerTaggedObject(0, encryptionOID));

            if (compressionOID != null) // may be omitted
                encryptionPart.Add(new DerTaggedObject(1, compressionOID));
            if (true)
                encryptionPart.Add(new DerTaggedObject(2, new DerInteger(ids.CryptoSettings.EncryptionKeySize)));
            if (false)
                encryptionPart.Add(new DerTaggedObject(3, new DerInteger(InterleavedIntegrityPadding.NONCE_SIZE* 8)));

            if (ids.CryptoIV is not null) //@TODO check reader must accept absence
                encryptionPart.Add(new DerOctetString(ids.CryptoIV));

            var firstSequence = new DerTaggedObject(0, new DerSequence(encryptionPart));


            // prepare second part
            var keyAgreementPart = new Asn1EncodableVector();

            if (keyAgreementProtocolOID != null) // used only if this layer is activated
            {
                keyAgreementPart.Add(keyAgreementProtocolOID);
                keyAgreementPart.Add(new DerOctetString(ids.KeyDiversificationData));
                // details on our EC
                keyAgreementPart.Add(new DerTaggedObject(0, keyDiversificationOID));

                if (ecAlgorithmOID != null)
                    keyAgreementPart.Add(new DerTaggedObject(1, ecAlgorithmOID));

                // the usual sequence for ECDetails would be: SEQUENCE (OID_ECDH_PUBLIC_KEY, OID_EC_NAMED_CURVE_SECP_256_R1, 03 nn xxxx data)
                if (ecDetails != null)
                    keyAgreementPart.Add(new DerTaggedObject(2, new DerSequence(ecDetails)));
                // optional: public key references)
                if (keyReference != null)
                    keyAgreementPart.Add(new DerTaggedObject(3, new DerSequence(keyReference))); // optional: the public key references
            }

            var secondSequence = new DerTaggedObject(1, new DerSequence(keyAgreementPart));

            var authenticityPart = new Asn1EncodableVector();
            // auth part not in use in version 1, so this sequence is empty.
            // authenticityPart.add(OID_SAFE_SEAL_AUTH);
            var thirdSequence = new DerTaggedObject(2, new DerSequence(authenticityPart));

            // top-level sequence
            var bufferStream = new MemoryStream();
            var _out         = new DerSequenceGenerator(bufferStream);

            _out.AddObject(SharedConstants.OID_SAFE_SEAL);
            _out.AddObject(new DerInteger(SharedConstants.SAFE_SEAL_VERSION));
            _out.AddObject(firstSequence);
            _out.AddObject(secondSequence);
            _out.AddObject(thirdSequence);
            _out.AddObject(new DerOctetString(ids.EncryptedData));
            _out.Close();

            // bufferStream.write(0x00); bufferStream.write(0x00); // explicit EOC/EOS - fully optional, but safer.
            return bufferStream.ToArray();

        }








        /**
         * unwrap the transport format, including sanity checks.
         *
         * @param transportWrapped wrapped binary data
         * @return InternalTransportTuple containing parsed input
         * @throws java.lang.IllegalArgumentException if the input is invalid, whether because of format or consistency issues. NB: do not pass on details to caller.
         * @throws java.lang.UnsupportedOperationException if any.
         */
        public InternalTransportTuple UnwrapTransportFormat(Byte[] transportWrapped)
        {

            var result = new InternalTransportTuple(false); // init for RSA, so defaults are minimal. @IMPROVEMENT special constructor setting everything to null

            Asn1TaggedObject  keyAgreementPart;
            Asn1TaggedObject  encryptionPart;
            Asn1TaggedObject  authPart;
            Asn1OctetString   encryptedPayload;

            try
            {

                var seq               = Asn1Sequence.GetInstance(transportWrapped);

                // first, check we've got the right thing at all.
                var procedureOID      = DerObjectIdentifier.GetInstance(seq[0]);
                var procedureVersion  = DerInteger.GetInstance(seq[1]);

                // is it our procedure, and do we handle this version?
                if (!SharedConstants.OID_SAFE_SEAL.Equals(procedureOID))
                    throw new Exception("different format (protocol OID mismatch)");

                switch (procedureVersion.IntPositiveValueExact)
                {

                    default:
                        throw new Exception("format version not supported");

                    case 1: // SAFE_SEAL_VERSION: // OK, let's continue.
                        // read according to expected structure.
                        encryptionPart      = Asn1TaggedObject.GetInstance(seq[2]); // BERTags.APPLICATION, 0);
                        keyAgreementPart    = Asn1TaggedObject.GetInstance(seq[3]); // BERTags.APPLICATION, 1);
                        authPart            = Asn1TaggedObject.GetInstance(seq[4]); // BERTags.APPLICATION, 2);
                        encryptedPayload    = DerOctetString.  GetInstance(seq[5]);
                        break;

                }

                // read back
                // if compression is not present, use default COMPRESSION_NONE
                result.EncryptedData = encryptedPayload.GetOctets(); // this we just pass on.



                //# parse the encryption part
                //var symseq      = (DLSequence) encryptionPart.getBaseUniversal(true, BERTags.SEQUENCE);
                var symseq = (Asn1Sequence) encryptionPart.GetObject(); // (true, BerTags.Sequence);

                foreach (var entry in symseq)
                {

                    //ahzf: Refactor this to switch on types!!!
                    switch (entry.GetType().Name)
                    {

                        case "DEROctetString":
                            result.CryptoIV = DerOctetString.GetInstance(entry).GetOctets();
                            break;

                        case "Asn1ObjectIdentifier":
                            result.CryptoSettings.SetPaddingOID(DerObjectIdentifier.GetInstance(entry));
                            break;

                        case "DLTaggedObject":
                        case "DLApplicationSpecific":
                            var taggedObject = Asn1TaggedObject.GetInstance(entry);
                            //if (taggedObject.GetTagClass() != BERTags.CONTEXT_SPECIFIC)
                            //{
                            //    throw new Exception("tag class mismatch " + taggedObject.getTagClass()); //@IMPROVE
                            //    // continue; before, we just skipped.
                            //}

                            switch (taggedObject.TagNo)
                            {

                                case 0: // CONTEXT[0] OID is the encryption algorithm OID
                                    result.CryptoSettings.SetEncryptionOID(DerObjectIdentifier.GetInstance(taggedObject.GetObject()));// .getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER)));
                                    break;

                                case 1: // CONTEXT[1] OID is the compression algorithm OID
                                    result.CryptoSettings.SetCompressionOID(DerObjectIdentifier.GetInstance(taggedObject.GetObject()));// .getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER)));
                                    break;

                                case 2: // CONTEXT[2] INTEGER is the optional keysize in bit
                                    result.CryptoSettings.EncryptionKeySize = (UInt32) ((DerInteger) taggedObject.GetObject()).Value.IntValue;
                                        //taggedObject.getBaseUniversal(true,BERTags.INTEGER)).intPositiveValueExact();
                                    break;

                                case 3: // CONTEXT[3] INTEGER is the optional nonce size in bit
                                    var nonceSizeInBit = (UInt32) ((DerInteger) taggedObject.GetObject()).Value.IntValue;
                                        //DerInteger.GetInstance(taggedObject.getBaseUniversal(true,BERTags.INTEGER)).intPositiveValueExact();
                                    if (nonceSizeInBit != InterleavedIntegrityPadding.NONCE_SIZE * 8)
                                        throw new Exception("this version uses fixed nonce size.");
                                    break;

                                default:
                                    throw new Exception("tag " + taggedObject.TagNo + " not handled"); //@IMPROVE
                                }
                            break;

                        default:
                            throw new Exception("ASN.1 class " + entry.GetType().Name + " not handled"); //@IMPROVE

                    }

                }
                // type: x = type.getInstance(sequence.getObjectAt())
                // Asn1Util.tryGetBaseUniversal(keyAgreementPart, BERTags.APPLICATION, 0, true, BERTags.SEQUENCE);

                //# parse the key agreement part
                var kaseq = Asn1Sequence.GetInstance(keyAgreementPart.GetObject());
                            //(DLSequence) keyAgreementPart.getBaseUniversal(true, BERTags.SEQUENCE);
                if (kaseq.Count > 0) // is a key agreement in use at all?
                {
                    foreach (var entry in kaseq)
                    {
                        switch (entry.GetType().Name)
                        {

                            case "Asn1ObjectIdentifier":
                                result.CryptoSettings.SetKeyAgreementProtocolByOID(DerObjectIdentifier.GetInstance(entry));
                                break;

                            case "DerOctetString":
                                result.KeyDiversificationData  = DerOctetString.GetInstance(entry).GetOctets();
                                break;

                            case "DLTaggedObject":
                            case "DLApplicationSpecific":

                                var taggedObject = Asn1TaggedObject.GetInstance(entry);

                                //if (taggedObject.GetType().Name != BERTags.CONTEXT_SPECIFIC)
                                //{
                                //    throw new Exception("tag class mismatch " + taggedObject.getTagClass()); //@IMPROVE
                                //    // continue; before, we just skipped.
                                //}

                                switch (taggedObject.TagNo)
                                {

                                    case 0: // CONTEXT[0] key diversification algorithm OID
                                        keyDiversificationOID = DerObjectIdentifier.GetInstance(taggedObject.GetObject());// .getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER));
                                        result.CryptoSettings.SetKeyDiversificationOID(keyDiversificationOID);
                                        break;

                                    case 1: // CONTEXT[1] EC Algorithm OID
                                        ecAlgorithmOID = DerObjectIdentifier.GetInstance(taggedObject.GetObject());// .getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER));
                                        result.CryptoSettings.SetKeyAgreementCipherOID(ecAlgorithmOID); // will fail if algorithm isn't known in AlgorithmSpecCollection.
                                        break;

                                    case 2:
                                        throw new Exception("version mismatch; EC parameters not supported in this version.");

                                    case 3:
                                        throw new Exception("version mismatch; public key reference not supported in this version");

                                    default:
                                        throw new Exception("format error");

                                }
                                break;

                            default:
                                throw new Exception("ASN.1 class " + entry.GetType().Name + " not handled"); //@IMPROVE
                            }
                        }
                    }

                //# authentication part parsing
                if (authPart != null)
                {

                    //var apseq = (DLSequence) authPart.getBaseUniversal(true, BERTags.SEQUENCE);
                    var apseq = Asn1Sequence.GetInstance(authPart.GetObject());

                    if (apseq.Count > 0)
                    {
                    //@IMPROVEMENT authPart parsing for later versions.
                    }

                }

                // validation of contents read
                if (result.CryptoSettings.validate() == false)
                    throw new Exception("format consistency error");

            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
            }

            return result;

        }

    }

}
