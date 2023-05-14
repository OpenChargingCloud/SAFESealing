
#region Usings

using System.Diagnostics;

using Org.BouncyCastle.Asn1;

#endregion

namespace SAFESealing
{
    public class TransportFormatConverter
    {

        private DerObjectIdentifier?  keyAgreementProtocolOID;
        private DerObjectIdentifier?  ecAlgorithmOID;
        private DerObjectIdentifier?  keyDiversificationOID;
        private DerObjectIdentifier?  encryptionOID;
        private DerObjectIdentifier?  compressionOID;
        private Asn1Encodable?        keyReference; // or Asn1EncodableVector, depending


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

            Asn1EncodableVector? ecDetails = null; // details about the elliptic curve used, optional. not in current version.
            // see https://www.rfc-editor.org/rfc/rfc3279 for encoding of ECParameters

            keyReference = null; // key reference for the public key to be used. not in current version

            // using bouncy castle. easier with TLVIterator in a later version
            //----
            // prepare first part
            var encryptionPart = new Asn1EncodableVector {
                                     SharedConstants.OID_IIP_ALGORITHM, // or wrap in context[1] ?
                                     new DerTaggedObject(0, encryptionOID)
                                 };

            if (compressionOID is not null) // may be omitted
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

            if (keyAgreementProtocolOID is not null) // used only if this layer is activated
            {
                keyAgreementPart.Add(keyAgreementProtocolOID);
                keyAgreementPart.Add(new DerOctetString(ids.KeyDiversificationData));
                // details on our EC
                keyAgreementPart.Add(new DerTaggedObject(0, keyDiversificationOID));

                if (ecAlgorithmOID != null)
                    keyAgreementPart.Add(new DerTaggedObject(1, ecAlgorithmOID));

                // the usual sequence for ECDetails would be: SEQUENCE (OID_ECDH_PUBLIC_KEY, OID_EC_NAMED_CURVE_SECP_256_R1, 03 nn xxxx data)
                if (ecDetails is not null)
                    keyAgreementPart.Add(new DerTaggedObject(2, new DerSequence(ecDetails)));
                // optional: public key references)
                if (keyReference is not null)
                    keyAgreementPart.Add(new DerTaggedObject(3, new DerSequence(keyReference))); // optional: the public key references
            }

            var secondSequence        = new DerTaggedObject(1, new DerSequence(keyAgreementPart));

            var authenticityPart      = new Asn1EncodableVector();
            // auth part not in use in version 1, so this sequence is empty.
            // authenticityPart.add(OID_SAFE_SEAL_AUTH);
            var thirdSequence         = new DerTaggedObject(2, new DerSequence(authenticityPart));

            // top-level sequence
            var bufferStream          = new MemoryStream();
            var derSequenceGenerator  = new DerSequenceGenerator(bufferStream);

            derSequenceGenerator.AddObject(SharedConstants.OID_SAFE_SEAL);
            derSequenceGenerator.AddObject(new DerInteger(SharedConstants.SAFE_SEAL_VERSION));
            derSequenceGenerator.AddObject(firstSequence);
            derSequenceGenerator.AddObject(secondSequence);
            derSequenceGenerator.AddObject(thirdSequence);
            derSequenceGenerator.AddObject(new DerOctetString(ids.EncryptedData));
            derSequenceGenerator.Close();

            // bufferStream.write(0x00); bufferStream.write(0x00); // explicit EOC/EOS - fully optional, but safer.
            return bufferStream.ToArray();

        }








        /**
         * unwrap the transport format, including sanity checks.
         *
         * @param transportWrapped wrapped binary data
         * @return InternalTransportTuple containing parsed input
         */
        public InternalTransportTuple? UnwrapTransportFormat(Byte[] TransportWrapped)
        {

            Asn1TaggedObject  keyAgreementPart;
            Asn1TaggedObject  encryptionPart;
            Asn1TaggedObject  authPart;
            Asn1OctetString   encryptedPayload;

            try
            {

                var seq                     = Asn1Sequence.GetInstance(TransportWrapped);

                // first, check we've got the right thing at all.
                var protocolIdentification  = DerObjectIdentifier.GetInstance(seq[0]);   // 1.3.6.1.4.1.60279.1.1 => S.A.F.E. e.V. IANA Private Enterprise Number
                var protocolVersion         = DerInteger.         GetInstance(seq[1]);   // 1                     => SAFE Sealing version

                // is it our procedure, and do we handle this version?
                if (!SharedConstants.OID_SAFE_SEAL.Equals(protocolIdentification))
                    throw new Exception($"Unkown protocol identification '{protocolIdentification.Id}'!");

                switch (protocolVersion.IntPositiveValueExact)
                {

                    case 1: // SAFE_SEAL_VERSION: // OK, let's continue.
                        // read according to expected structure.
                        encryptionPart      = Asn1TaggedObject.GetInstance(seq[2]); // BERTags.APPLICATION, 0);
                        keyAgreementPart    = Asn1TaggedObject.GetInstance(seq[3]); // BERTags.APPLICATION, 1);
                        authPart            = Asn1TaggedObject.GetInstance(seq[4]); // BERTags.APPLICATION, 2);
                        encryptedPayload    = DerOctetString.  GetInstance(seq[5]);
                        break;

                    default:
                        throw new Exception($"Unkown protocol version '{protocolVersion.IntPositiveValueExact}'!");

                }

                // read back
                // if compression is not present, use default COMPRESSION_NONE
                var encryptedData           = encryptedPayload.GetOctets();

                var cryptoIV                = Array.Empty<Byte>();
                var keyDiversificationData  = Array.Empty<Byte>();
                var cryptoSettings          = new CryptoSettingsStruct();


                //# parse the encryption part
                //var symseq      = (DLSequence) encryptionPart.getBaseUniversal(true, BERTags.SEQUENCE);
                var symseq = (Asn1Sequence) encryptionPart.GetObject(); // (true, BerTags.Sequence);

                foreach (var entry in symseq)
                {

                    //ahzf: Refactor this to switch on types!!!
                    switch (entry.GetType().Name)
                    {

                        case "DerOctetString":
                            cryptoIV = DerOctetString.GetInstance(entry).GetOctets();
                            break;

                        case "DerObjectIdentifier":
                            cryptoSettings.SetPaddingOID(DerObjectIdentifier.GetInstance(entry));
                            break;

                        case "DerTaggedObject":
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
                                    cryptoSettings.SetEncryptionOID(DerObjectIdentifier.GetInstance(taggedObject.GetObject()));// .getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER)));
                                    break;

                                case 1: // CONTEXT[1] OID is the compression algorithm OID
                                    cryptoSettings.SetCompressionOID(DerObjectIdentifier.GetInstance(taggedObject.GetObject()));// .getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER)));
                                    break;

                                case 2: // CONTEXT[2] INTEGER is the optional keysize in bit
                                    cryptoSettings.EncryptionKeySize = (UInt32) ((DerInteger) taggedObject.GetObject()).Value.IntValue;
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
                                cryptoSettings.SetKeyAgreementProtocolByOID(DerObjectIdentifier.GetInstance(entry));
                                break;

                            case "DerOctetString":
                                keyDiversificationData = DerOctetString.GetInstance(entry).GetOctets();
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
                                        cryptoSettings.SetKeyDiversificationOID(keyDiversificationOID);
                                        break;

                                    case 1: // CONTEXT[1] EC Algorithm OID
                                        ecAlgorithmOID = DerObjectIdentifier.GetInstance(taggedObject.GetObject());// .getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER));
                                        cryptoSettings.SetKeyAgreementCipherOID(ecAlgorithmOID); // will fail if algorithm isn't known in AlgorithmSpecCollection.
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
                if (authPart is not null)
                {

                    //var apseq = (DLSequence) authPart.getBaseUniversal(true, BERTags.SEQUENCE);
                    var apseq = Asn1Sequence.GetInstance(authPart.GetObject());

                    if (apseq.Count > 0)
                    {
                    //@IMPROVEMENT authPart parsing for later versions.
                    }

                }

                var itt = new InternalTransportTuple(cryptoSettings,
                                                     cryptoIV,
                                                     encryptedData,
                                                     keyDiversificationData);

                // validation of contents read
                if (itt.CryptoSettings.validate() == false)
                    throw new Exception("format consistency error");

                return itt;

            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
            }

            return null;

        }

    }

}
