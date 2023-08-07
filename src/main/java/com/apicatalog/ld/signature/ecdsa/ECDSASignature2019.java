package com.apicatalog.ld.signature.ecdsa;

import java.net.URI;
import java.time.Instant;

import com.apicatalog.jsonld.schema.LdObject;
import com.apicatalog.jsonld.schema.LdProperty;
import com.apicatalog.jsonld.schema.LdSchema;
import com.apicatalog.jsonld.schema.LdTerm;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.ld.signature.CryptoSuite;
import com.apicatalog.ld.signature.VerificationMethod;
import com.apicatalog.ld.signature.ecdsa.BCECDSASignatureProvider.CurveType;
import com.apicatalog.ld.signature.primitive.MessageDigest;
import com.apicatalog.ld.signature.primitive.Urdna2015;
import com.apicatalog.multibase.Multibase.Algorithm;
import com.apicatalog.multicodec.Multicodec.Codec;
import com.apicatalog.vc.VcVocab;
import com.apicatalog.vc.integrity.DataIntegrityProof;
import com.apicatalog.vc.integrity.DataIntegritySchema;
import com.apicatalog.vc.integrity.DataIntegritySuite;

public final class ECDSASignature2019 extends DataIntegritySuite {

    static final CryptoSuite CRYPTO_256 = new CryptoSuite(
            new Urdna2015(),
            new MessageDigest("SHA-256"),
            new BCECDSASignatureProvider(CurveType.P256)
            );

    static final CryptoSuite CRYPTO_384 = new CryptoSuite(
            new Urdna2015(),
            new MessageDigest("SHA-384"),
            new BCECDSASignatureProvider(CurveType.P384));

    static final CryptoSuite CRYPTO_512 = new CryptoSuite(
            new Urdna2015(),
            new MessageDigest("SHA-512"),
            new BCECDSASignatureProvider(CurveType.P512));

    public static final LdTerm VERIFICATION_KEY_TYPE = LdTerm.create("ECDSAVerificationKey2019", VcVocab.SECURITY_VOCAB);

    public static final LdTerm KEY_PAIR_TYPE = LdTerm.create("ECDSAKeyPair2019", VcVocab.SECURITY_VOCAB);

    static final LdSchema METHOD_SCHEMA = DataIntegritySchema.getVerificationKey(
            VERIFICATION_KEY_TYPE,
            DataIntegritySchema.getPublicKey(
                    Algorithm.Base58Btc,
                    Codec.P256PublicKey,
                    key -> key == null || (key.length == 32
                            || key.length == 57
                            || key.length == 114)));

    static final LdProperty<byte[]> PROOF_VALUE_PROPERTY = DataIntegritySchema.getProofValue(
            Algorithm.Base58Btc,
            key -> key.length == 64);

    public ECDSASignature2019() {
        super("ecdsa-2019", METHOD_SCHEMA, PROOF_VALUE_PROPERTY);
    }

    @Override
    protected CryptoSuite getCryptoSuite(LdObject ldProof) throws DocumentError {
        
        byte[] proofValue = ldProof.value(DataIntegritySchema.PROOF_VALUE);;
        
        if (proofValue == null) {
            throw new DocumentError(ErrorType.Missing, DataIntegritySchema.PROOF_VALUE.name());
        }
        
        if (proofValue.length == 64) {
            return CRYPTO_256;
        }
        if (proofValue.length == 96) {
            return CRYPTO_512;
        }
        
        throw new DocumentError(ErrorType.Invalid, DataIntegritySchema.PROOF_VALUE.name());
    }

    public DataIntegrityProof createP256Draft(
            VerificationMethod verificationMethod,
            URI purpose,
            Instant created,
            String domain,
            String challenge) throws DocumentError {
        return super.createDraft(CRYPTO_256, verificationMethod, purpose, created, domain, challenge);
    }
    
    public DataIntegrityProof createP384Draft(
            VerificationMethod verificationMethod,
            URI purpose,
            Instant created,
            String domain,
            String challenge) throws DocumentError {
        return super.createDraft(CRYPTO_384, verificationMethod, purpose, created, domain, challenge);
    }
    
    public DataIntegrityProof createP512Draft(
            VerificationMethod verificationMethod,
            URI purpose,
            Instant created,
            String domain,
            String challenge) throws DocumentError {
        return super.createDraft(CRYPTO_512, verificationMethod, purpose, created, domain, challenge);
    }
}