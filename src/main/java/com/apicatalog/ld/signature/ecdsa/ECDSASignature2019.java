package com.apicatalog.ld.signature.ecdsa;

import java.net.URI;
import java.time.Instant;

import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.ld.signature.CryptoSuite;
import com.apicatalog.ld.signature.VerificationMethod;
import com.apicatalog.ld.signature.ecdsa.BCECDSASignatureProvider.CurveType;
import com.apicatalog.ld.signature.primitive.MessageDigest;
import com.apicatalog.ld.signature.primitive.Urdna2015;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.multikey.MultiKey;
import com.apicatalog.multikey.MultiKeyAdapter;
import com.apicatalog.vc.integrity.DataIntegrityProof;
import com.apicatalog.vc.integrity.DataIntegritySuite;
import com.apicatalog.vc.method.MethodAdapter;

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
            if (method.publicKey() != null) {
            System.out.println(">>>> " + method.publicKey().length);
            }
            if (method.publicKey() != null
                    && method.publicKey().length != 32
                    && method.publicKey().length != 57
//                    && method.publicKey().length != 114
            ) {
//                throw new DocumentError(ErrorType.Invalid, "PublicKeyLength");
            }
        };
    };

    public ECDSASignature2019() {
        super(CRYPTOSUITE_NAME, METHOD_ADAPTER);
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

    @Override
    protected CryptoSuite getCryptoSuite(String cryptoName, byte[] proofValue) throws DocumentError {
        if (proofValue != null) {
            if (proofValue.length == 64) {
                return CRYPTO_256;
            }
            if (proofValue.length == 96) {
                return CRYPTO_384;
            }
        }
        return CRYPTO_256;
    }

    @Override
    protected void validateProofValue(byte[] proofValue) throws DocumentError {
        if (proofValue != null && proofValue.length != 64) {
            throw new DocumentError(ErrorType.Invalid, "ProofValueLenght");
        }
    }

}