package com.apicatalog.ld.signature.ecdsa;

import java.net.URI;

import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.ld.signature.CryptoSuite;
import com.apicatalog.ld.signature.VerificationMethod;
import com.apicatalog.ld.signature.ecdsa.BCECDSASignatureProvider.CurveType;
import com.apicatalog.ld.signature.key.KeyPair;
import com.apicatalog.ld.signature.primitive.MessageDigest;
import com.apicatalog.ld.signature.primitive.Urdna2015;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.multikey.MultiKey;
import com.apicatalog.multikey.MultiKeyAdapter;
import com.apicatalog.vc.integrity.DataIntegrityProofDraft;
import com.apicatalog.vc.integrity.DataIntegritySuite;
import com.apicatalog.vc.issuer.Issuer;
import com.apicatalog.vc.method.MethodAdapter;
import com.apicatalog.vc.proof.ProofValue;
import com.apicatalog.vc.solid.SolidIssuer;
import com.apicatalog.vc.solid.SolidProofValue;

public final class ECDSASignature2019 extends DataIntegritySuite {

    static final CryptoSuite CRYPTO_256 = new CryptoSuite(
            new Urdna2015(),
            new MessageDigest("SHA-256"),
            new BCECDSASignatureProvider(CurveType.P256));

    static final CryptoSuite CRYPTO_384 = new CryptoSuite(
            new Urdna2015(),
            new MessageDigest("SHA-384"),
            new BCECDSASignatureProvider(CurveType.P384));

    public static final String CRYPTOSUITE_NAME = "ecdsa-rdfc-2019";

    public static final MulticodecDecoder CODECS = MulticodecDecoder.getInstance(
            KeyCodec.P256_PUBLIC_KEY,
            KeyCodec.P256_PRIVATE_KEY,
            KeyCodec.P384_PUBLIC_KEY,
            KeyCodec.P384_PRIVATE_KEY);

    public static final MethodAdapter METHOD_ADAPTER = new MultiKeyAdapter(CODECS) {

        @Override
        protected Multicodec getPublicKeyCodec(String algo, int keyLength) {
            if (keyLength == 32) {
                return KeyCodec.P256_PUBLIC_KEY;
            }
            if (keyLength == 57) {
                return KeyCodec.P384_PUBLIC_KEY;
            }
            throw new IllegalStateException();
        }

        @Override
        protected Multicodec getPrivateKeyCodec(String algo, int keyLength) {
            throw new UnsupportedOperationException();
        }

        protected void validate(MultiKey method) throws DocumentError {
            if (method.publicKey() != null
                    && method.publicKey().length != 33 // P-256
                    && method.publicKey().length != 49 // P-384
            ) {
                throw new DocumentError(ErrorType.Invalid, "PublicKeyLength");
            }
        };
    };

    public ECDSASignature2019() {
        super(CRYPTOSUITE_NAME, Multibase.BASE_58_BTC, METHOD_ADAPTER);
    }

    public DataIntegrityProofDraft createP256Draft(
            VerificationMethod verificationMethod,
            URI purpose) throws DocumentError {
        return new DataIntegrityProofDraft(this, CRYPTO_256, verificationMethod, purpose);
    }

    public DataIntegrityProofDraft createP256Draft(
            URI verificationMethod,
            URI purpose) throws DocumentError {
        return new DataIntegrityProofDraft(this, CRYPTO_256, verificationMethod, purpose);
    }

    public DataIntegrityProofDraft createP384Draft(
            VerificationMethod verificationMethod,
            URI purpose) throws DocumentError {
        return new DataIntegrityProofDraft(this, CRYPTO_384, verificationMethod, purpose);
    }

    public DataIntegrityProofDraft createP384Draft(
            URI verificationMethod,
            URI purpose) throws DocumentError {
        return new DataIntegrityProofDraft(this, CRYPTO_384, verificationMethod, purpose);
    }

    @Override
    public Issuer createIssuer(KeyPair keyPair) {
        return new SolidIssuer(this, keyPair, proofValueBase);
    }

    @Override
    protected ProofValue getProofValue(byte[] proofValue, DocumentLoader loader) throws DocumentError {
        if (proofValue != null && proofValue.length != 64 && proofValue.length != 96) {
            throw new DocumentError(ErrorType.Invalid, "ProofValueLenght");
        }
        return new SolidProofValue(proofValue);
    }

    @Override
    protected CryptoSuite getCryptoSuite(String cryptoName, ProofValue proofValue) throws DocumentError {

        if (proofValue != null) {
            final byte[] value = ((SolidProofValue) proofValue).toByteArray();
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