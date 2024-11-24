package com.apicatalog.ld.signature.ecdsa;

import java.net.URI;
import java.util.Objects;

import com.apicatalog.controller.key.KeyPair;
import com.apicatalog.cryptosuite.CryptoSuite;
import com.apicatalog.cryptosuite.primitive.MessageDigest;
import com.apicatalog.cryptosuite.primitive.Urdna2015;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.ld.signature.ecdsa.BCECDSASignatureProvider.CurveType;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.vc.issuer.Issuer;
import com.apicatalog.vc.model.VerifiableMaterial;
import com.apicatalog.vc.proof.ProofValue;
import com.apicatalog.vc.solid.SolidIssuer;
import com.apicatalog.vc.solid.SolidProofValue;
import com.apicatalog.vcdi.DataIntegrityProofDraft;
import com.apicatalog.vcdi.DataIntegritySuite;

public final class ECDSASignature2019 extends DataIntegritySuite {

    public static final String CRYPTOSUITE_NAME = "ecdsa-rdfc-2019";

    static final CryptoSuite CRYPTO_256 = new CryptoSuite(
            "ecdsa-rdfc-2019-p256",
            256,
            new Urdna2015(),
            new MessageDigest("SHA-256"),
            new BCECDSASignatureProvider(CurveType.P256));

    static final CryptoSuite CRYPTO_384 = new CryptoSuite(
            "ecdsa-rdfc-2019-p384",
            384,
            new Urdna2015(),
            new MessageDigest("SHA-384"),
            new BCECDSASignatureProvider(CurveType.P384));

    public static final MulticodecDecoder CODECS = MulticodecDecoder.getInstance(
            KeyCodec.P256_PUBLIC_KEY,
            KeyCodec.P256_PRIVATE_KEY,
            KeyCodec.P384_PUBLIC_KEY,
            KeyCodec.P384_PRIVATE_KEY);

//    public static final MethodAdapter METHOD_ADAPTER = new MultiKeyAdapter(CODECS) {
//
//        @Override
//        protected Multicodec getPublicKeyCodec(String algo, int keyLength) {
//            if (keyLength == 32) {
//                return KeyCodec.P256_PUBLIC_KEY;
//            }
//            if (keyLength == 57) {
//                return KeyCodec.P384_PUBLIC_KEY;
//            }
//            throw new IllegalStateException();
//        }
//
//        protected void validate(MultiKey method) throws DocumentError {
//            if (method.publicKey() != null
//                    && method.publicKey().length != 33 // P-256
//                    && method.publicKey().length != 49 // P-384
//            ) {
//                throw new DocumentError(ErrorType.Invalid, "PublicKeyLength");
//            }
//        };

    public ECDSASignature2019() {
        super(CRYPTOSUITE_NAME, Multibase.BASE_58_BTC);
    }

//    public DataIntegrityProofDraft createP256Draft(
//            VerificationMethod verificationMethod,
//            URI purpose) throws DocumentError {
//        return new DataIntegrityProofDraft(this, CRYPTO_256, verificationMethod, purpose);
//    }
//
//    public DataIntegrityProofDraft createP256Draft(
//            URI verificationMethod,
//            URI purpose) throws DocumentError {
//        return new DataIntegrityProofDraft(this, CRYPTO_256, verificationMethod, purpose);
//    }
//
//    public DataIntegrityProofDraft createP384Draft(
//            VerificationMethod verificationMethod,
//            URI purpose) throws DocumentError {
//        return new DataIntegrityProofDraft(this, CRYPTO_384, verificationMethod, purpose);
//    }
//
//    // TODO move to issuer
//    public DataIntegrityProofDraft createP384Draft(
//            URI verificationMethod,
//            URI purpose) throws DocumentError {
//        return new DataIntegrityProofDraft(this, CRYPTO_384, verificationMethod, purpose);
//    }

    @Override
    protected ProofValue getProofValue(VerifiableMaterial verifiable, VerifiableMaterial proof, byte[] proofValue, DocumentLoader loader, URI base) throws DocumentError {

        if (proofValue == null) {
            return null;
        }

        CryptoSuite crypto = null;

        if (proofValue.length == 64) {
            crypto = CRYPTO_256;

        } else if (proofValue.length == 96) {
            crypto = CRYPTO_384;

        } else {
            throw new DocumentError(ErrorType.Invalid, "ProofValueLength");
        }

        return SolidProofValue.of(crypto, verifiable, proof, proofValue);
    }

    @Override
    public Issuer createIssuer(KeyPair keyPair) {
        
        Objects.requireNonNull(keyPair);
        
        final CryptoSuite crypto;

        if (keyPair.privateKey().rawBytes().length == 32) {
            crypto = CRYPTO_256;

        } else if (keyPair.privateKey().rawBytes().length != 48) {
            crypto = CRYPTO_384;

        } else {
            throw new IllegalArgumentException("Cannot detect key pair type, expected P-256 or P-384.");
        }
        
        return new SolidIssuer(
                this, 
                crypto, 
                keyPair, 
                proofValueBase,
                method -> new DataIntegrityProofDraft(this, crypto, method)
                );
    }

    @Override
    protected CryptoSuite getCryptoSuite(String cryptoName, ProofValue proofValue) throws DocumentError {
        if (!CRYPTOSUITE_NAME.equals(cryptoName)) {
            return null;
        }        
        
        if (proofValue != null) {
            final byte[] value = ((SolidProofValue) proofValue).signature().value();
            if (value != null) {
                if (value.length == 64) {
                    return CRYPTO_256;
                }
                if (value.length == 96) {
                    return CRYPTO_384;
                }
            }
        }
        return CRYPTO_256;
    }
}