package com.apicatalog.ld.signature.ecdsa;

import java.net.URI;
import java.util.Objects;

import com.apicatalog.controller.key.KeyPair;
import com.apicatalog.cryptosuite.CryptoSuite;
import com.apicatalog.cryptosuite.primitive.MessageDigest;
import com.apicatalog.cryptosuite.primitive.RDFC;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.ld.signature.ecdsa.BCECDSASignatureProvider.CurveType;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.vc.di.DataIntegrityDraft;
import com.apicatalog.vc.di.DataIntegritySuite;
import com.apicatalog.vc.issuer.Issuer;
import com.apicatalog.vc.model.DocumentError;
import com.apicatalog.vc.model.DocumentModel;
import com.apicatalog.vc.model.VerifiableMaterial;
import com.apicatalog.vc.model.DocumentError.ErrorType;
import com.apicatalog.vc.proof.Proof;
import com.apicatalog.vc.proof.ProofValue;
import com.apicatalog.vc.solid.SolidIssuer;
import com.apicatalog.vc.solid.SolidProofValue;

public final class ECDSARdfc2019Suite extends DataIntegritySuite {

    public static final String CRYPTOSUITE_NAME = "ecdsa-rdfc-2019";

    static final CryptoSuite CRYPTO_256 = new CryptoSuite(
            CRYPTOSUITE_NAME,
            256,
            new RDFC(),
            new MessageDigest("SHA-256"),
            new BCECDSASignatureProvider(CurveType.P256));

    static final CryptoSuite CRYPTO_384 = new CryptoSuite(
            CRYPTOSUITE_NAME,
            384,
            new RDFC(),
            new MessageDigest("SHA-384"),
            new BCECDSASignatureProvider(CurveType.P384));

    public static final MulticodecDecoder CODECS = MulticodecDecoder.getInstance(
            KeyCodec.P256_PUBLIC_KEY,
            KeyCodec.P256_PRIVATE_KEY,
            KeyCodec.P384_PUBLIC_KEY,
            KeyCodec.P384_PRIVATE_KEY);

    public ECDSARdfc2019Suite() {
        super(CRYPTOSUITE_NAME, Multibase.BASE_58_BTC);
    }

    @Override
    protected ProofValue getProofValue(Proof proof, DocumentModel model, byte[] proofValue, DocumentLoader loader, URI base) throws DocumentError {

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

        
        VerifiableMaterial verifiable =  model.data();
        VerifiableMaterial unsignedProof = model.proofs().iterator().next();
        
        return SolidProofValue.of(crypto, verifiable, unsignedProof, proofValue, proof);
    }

    @Override
    public Issuer createIssuer(KeyPair keyPair) {

        Objects.requireNonNull(keyPair);

        final CryptoSuite crypto;

        if (keyPair.privateKey().rawBytes().length == 32) {
            crypto = CRYPTO_256;

        } else if (keyPair.privateKey().rawBytes().length == 48) {
            crypto = CRYPTO_384;

        } else {
            throw new IllegalArgumentException("Cannot detect key pair type, expected P-256 or P-384 but got key length of " + keyPair.privateKey().rawBytes().length + " bytes.");
        }

        return new SolidIssuer(
                this,
                crypto,
                keyPair,
                proofValueBase,
                method -> new DataIntegrityDraft(this, crypto, method));
    }

    @Override
    protected CryptoSuite getCryptoSuite(String cryptoName, ProofValue proofValue) throws DocumentError {
        if (!CRYPTOSUITE_NAME.equals(cryptoName)) {
            return null;
        }

        if (proofValue != null) {
            if (proofValue instanceof SolidProofValue solidValue) {
                final byte[] byteArray = solidValue.signature().byteArrayValue();
                if (byteArray != null) {
                    if (byteArray.length == 64) {
                        return CRYPTO_256;
                    }
                    if (byteArray.length == 96) {
                        return CRYPTO_384;
                    }
                    throw new DocumentError(ErrorType.Invalid, "ProofValueLength");
                }
                throw new DocumentError(ErrorType.Unknown, "ProofValue");
            }
        }
        return CRYPTO_256;
    }
}