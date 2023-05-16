
#region Usings

using System.Diagnostics;

using Org.BouncyCastle.Asn1;

#endregion

namespace SAFESealing
{

    /// <summary>
    /// Transport format converter.
    /// </summary>
    public static class TransportFormatConverter
    {

        #region (static) WrapForTransport     (TransportTuple)

        /// <summary>
        /// Wrap for transport
        /// </summary>
        /// <param name="TransportTuple">An internal transport tuple.</param>
        public static ByteArray WrapForTransport(InternalTransportTuple TransportTuple)
        {

            #region Encryption    Sequence

            var encryptionOID            = TransportTuple.CryptoSettings.Encryption?.OID;
            var encryptionPart           = new Asn1EncodableVector {
                                               SharedConstants.OID_IIP_ALGORITHM, // or wrap in context[1] ?
                                               new DerTaggedObject(0, encryptionOID)
                                           };

            var compressionOID           = TransportTuple.CryptoSettings.Compression?.OID;
            if (compressionOID is not null) // may be omitted
                encryptionPart.Add(new DerTaggedObject(1, compressionOID));

            if (true)
                encryptionPart.Add(new DerTaggedObject(2, new DerInteger(TransportTuple.CryptoSettings.EncryptionKeySize.Value)));

            if (false)
                encryptionPart.Add(new DerTaggedObject(3, new DerInteger(InterleavedIntegrityPadding.NONCE_SIZE* 8)));

            if (TransportTuple.CryptoIV is not null) //@TODO check reader must accept absence
                encryptionPart.Add(new DerOctetString(TransportTuple.CryptoIV));

            var encryptionSequence       = new DerTaggedObject(0, new DerSequence(encryptionPart));

            #endregion

            #region Key Agreement Sequence

            var keyAgreementProtocolOID  = TransportTuple.CryptoSettings.KeyAgreementProtocol?.OID;
            var keyAgreementPart         = new Asn1EncodableVector();

            if (keyAgreementProtocolOID is not null) // used only if this layer is activated
            {

                keyAgreementPart.Add(keyAgreementProtocolOID);
                keyAgreementPart.Add(new DerOctetString(TransportTuple.KeyDiversificationData));

                // details on our EC
                var keyDiversificationOID  = TransportTuple.CryptoSettings.KeyDiversificationAlgorithm?.OID;
                keyAgreementPart.Add(new DerTaggedObject(0, keyDiversificationOID));

                // see https://www.rfc-editor.org/rfc/rfc3279 for encoding of ECParameters
                var ecAlgorithmOID         = TransportTuple.CryptoSettings.KeyAgreementCipher?.OID;
                if (ecAlgorithmOID is not null)
                    keyAgreementPart.Add(new DerTaggedObject(1, ecAlgorithmOID));

                // Details about the elliptic curve used, optional.
                // Not in current version!
                // The usual sequence for ECDetails would be: SEQUENCE (OID_ECDH_PUBLIC_KEY, OID_EC_NAMED_CURVE_SECP_256_R1, 03 nn xxxx data)
                Asn1EncodableVector? ecDetails      = null;
                if (ecDetails is not null)
                    keyAgreementPart.Add(new DerTaggedObject(2, new DerSequence(ecDetails)));

                // Public key reference for the public key to be used.
                // Not in current version!
                Asn1Encodable?       keyReference   = null;
                if (keyReference is not null)
                    keyAgreementPart.Add(new DerTaggedObject(3, new DerSequence(keyReference))); // optional: the public key references

            }

            var keyAgreementSequence     = new DerTaggedObject(1, new DerSequence(keyAgreementPart));

            #endregion

            #region Authenticity  Sequence

            var authenticityPart         = new Asn1EncodableVector();

            // auth part not in use in version 1, so this sequence is empty.
            // authenticityPart.add(OID_SAFE_SEAL_AUTH);
            var authenticitySequence     = new DerTaggedObject(2, new DerSequence(authenticityPart));

            #endregion

            #region Top-Level     Sequence

            var bufferStream             = new MemoryStream();
            var derSequenceGenerator     = new DerSequenceGenerator(bufferStream);

            derSequenceGenerator.AddObject(               SharedConstants.OID_SAFE_SEAL);
            derSequenceGenerator.AddObject(new DerInteger(SharedConstants.SAFE_SEAL_VERSION));
            derSequenceGenerator.AddObject(encryptionSequence);
            derSequenceGenerator.AddObject(keyAgreementSequence);
            derSequenceGenerator.AddObject(authenticitySequence);
            derSequenceGenerator.AddObject(new DerOctetString(TransportTuple.EncryptedData));

            derSequenceGenerator.Close();

            #endregion

            // bufferStream.write(0x00); bufferStream.write(0x00); // explicit EOC/EOS - fully optional, but safer.
            return ByteArray.Ok(bufferStream.ToArray());

        }

        #endregion

        #region (static) UnwrapTransportFormat(TransportWrapped)

        /// <summary>
        /// Unwrap the transport format, including sanity checks.
        /// </summary>
        /// <param name="TransportWrapped">Wrapped binary data.</param>
        public static (InternalTransportTuple?, String) UnwrapTransportFormat(Byte[] TransportWrapped)
        {

            try
            {

                #region Parse IIP header

                var iipHeaderSequence       = Asn1Sequence.       GetInstance(TransportWrapped);

                var protocolIdentification  = DerObjectIdentifier.GetInstance(iipHeaderSequence[0]);   // 1.3.6.1.4.1.60279.1.1 => S.A.F.E. e.V. IANA Private Enterprise Number
                var protocolVersion         = DerInteger.         GetInstance(iipHeaderSequence[1]);   // 1                     => SAFE Sealing version

                if (!SharedConstants.OID_SAFE_SEAL.Equals(protocolIdentification))
                    return (null, $"Unkown protocol identification '{protocolIdentification.Id}'!");

                #endregion

                #region Parse protocol version 1

                if (protocolVersion.IntPositiveValueExact == 1)
                {

                    var             encryptionPart                = Asn1TaggedObject.GetInstance(iipHeaderSequence[2]); // BERTags.APPLICATION, 0);
                    var             keyAgreementPart              = Asn1TaggedObject.GetInstance(iipHeaderSequence[3]); // BERTags.APPLICATION, 1);
                    var             authPart                      = Asn1TaggedObject.GetInstance(iipHeaderSequence[4]); // BERTags.APPLICATION, 2);
                    var             encryptedPayload              = DerOctetString.  GetInstance(iipHeaderSequence[5]);

                    // if compression is not present, use default COMPRESSION_NONE
                    var             encryptedData                 = encryptedPayload.GetOctets();

                    var             cryptoIV                      = Array.Empty<Byte>();
                    var             keyDiversificationData        = Array.Empty<Byte>();

                    AlgorithmSpec?  paddingAlgorithm              = null;
                    AlgorithmSpec?  encryptionAlgorithm           = null;
                    AlgorithmSpec?  compressionAlgorithm          = null;
                    AlgorithmSpec?  keyAgreementAlgorithm         = null;
                    AlgorithmSpec?  keyDiversificationAlgorithm   = null;
                    AlgorithmSpec?  keyAgreementCipherToUse       = null;
                    UInt32?         encryptionKeySize             = null;


                    #region Parse the encryption part

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
                                paddingAlgorithm = CryptoSettings.GetPaddingOID(DerObjectIdentifier.GetInstance(entry));
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
                                        encryptionAlgorithm  = CryptoSettings.GetEncryptionOID(DerObjectIdentifier.GetInstance(taggedObject.GetObject()));// .getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER)));
                                        break;

                                    case 1: // CONTEXT[1] OID is the compression algorithm OID
                                        compressionAlgorithm = CryptoSettings.GetCompressionOID(DerObjectIdentifier.GetInstance(taggedObject.GetObject()));// .getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER)));
                                        break;

                                    case 2: // CONTEXT[2] INTEGER is the optional keysize in bit
                                        encryptionKeySize = (UInt32) ((DerInteger) taggedObject.GetObject()).Value.IntValue;
                                            //taggedObject.getBaseUniversal(true,BERTags.INTEGER)).intPositiveValueExact();
                                        break;

                                    case 3: // CONTEXT[3] INTEGER is the optional nonce size in bit
                                        var nonceSizeInBit = (UInt32) ((DerInteger) taggedObject.GetObject()).Value.IntValue;
                                            //DerInteger.GetInstance(taggedObject.getBaseUniversal(true,BERTags.INTEGER)).intPositiveValueExact();
                                        if (nonceSizeInBit != InterleavedIntegrityPadding.NONCE_SIZE * 8)
                                            return (null, "this version uses fixed nonce size.");
                                        break;

                                    default:
                                        return (null, "tag " + taggedObject.TagNo + " not handled"); //@IMPROVE
                                    }
                                break;

                            default:
                                return (null, "ASN.1 class " + entry.GetType().Name + " not handled"); //@IMPROVE

                        }

                    }
                    // type: x = type.getInstance(sequence.getObjectAt())
                    // Asn1Util.tryGetBaseUniversal(keyAgreementPart, BERTags.APPLICATION, 0, true, BERTags.SEQUENCE);

                    #endregion

                    #region Parse the key agreement part

                    var kaseq = Asn1Sequence.GetInstance(keyAgreementPart.GetObject());
                                //(DLSequence) keyAgreementPart.getBaseUniversal(true, BERTags.SEQUENCE);
                    if (kaseq.Count > 0) // is a key agreement in use at all?
                    {
                        foreach (var entry in kaseq)
                        {
                            switch (entry.GetType().Name)
                            {

                                case "DerObjectIdentifier":
                                    keyAgreementAlgorithm = CryptoSettings.GetKeyAgreementProtocolByOID(DerObjectIdentifier.GetInstance(entry));
                                    break;

                                case "DerOctetString":
                                    keyDiversificationData = DerOctetString.GetInstance(entry).GetOctets();
                                    break;

                                case "DerTaggedObject":
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
                                            var keyDiversificationOID    = DerObjectIdentifier. GetInstance(taggedObject.GetObject());  // .getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER));
                                            keyDiversificationAlgorithm  = CryptoSettings.GetKeyDiversificationOID(keyDiversificationOID);
                                            break;

                                        case 1: // CONTEXT[1] EC Algorithm OID
                                            var ecAlgorithmOID           = DerObjectIdentifier. GetInstance(taggedObject.GetObject());  // .getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER));
                                            keyAgreementCipherToUse      = CryptoSettings.GetKeyAgreementCipherOID(ecAlgorithmOID);     // will fail if algorithm isn't known in AlgorithmSpecCollection.
                                            break;

                                        case 2:
                                            return (null, "version mismatch; EC parameters not supported in this version.");

                                        case 3:
                                            return (null, "version mismatch; public key reference not supported in this version");

                                        default:
                                            return (null, "format error");

                                    }
                                    break;

                                default:
                                    return (null, "ASN.1 class " + entry.GetType().Name + " not handled"); //@IMPROVE

                            }
                        }
                    }

                    #endregion

                    #region Parse the optional authentication part

                    if (authPart is not null)
                    {

                        //var apseq = (DLSequence) authPart.getBaseUniversal(true, BERTags.SEQUENCE);
                        var apseq = Asn1Sequence.GetInstance(authPart.GetObject());

                        if (apseq.Count > 0)
                        {
                        //@IMPROVEMENT authPart parsing for later versions.
                        }

                    }

                    #endregion


                    if (encryptionAlgorithm is null)
                        return (null, "The encryption algorithm must not be null!");

                    if (compressionAlgorithm is null)
                        return (null, "The compression algorithm must not be null!");

                    return (new InternalTransportTuple(new CryptoSettings(
                                                           KeyAgreementProtocolToUse:  keyAgreementAlgorithm,
                                                           KeyAgreementCipherToUse:    keyAgreementCipherToUse,
                                                           KeyDiversificationToUse:    keyDiversificationAlgorithm,
                                                           EncryptionToUse:            encryptionAlgorithm,
                                                           CompressionUsed:            compressionAlgorithm,
                                                           PaddingToUse:               paddingAlgorithm,
                                                           EncryptionKeySize:          encryptionKeySize
                                                       ),
                                                       cryptoIV,
                                                       encryptedData,
                                                       keyDiversificationData),
                            String.Empty);

                }

                #endregion

                else
                    return (null, $"Unkown protocol version '{protocolVersion.IntPositiveValueExact}'!");

            }
            catch (Exception e)
            {
                return (null, e.Message);
            }

        }

        #endregion

    }

}
