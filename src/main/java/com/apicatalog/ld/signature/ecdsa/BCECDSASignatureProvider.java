package com.apicatalog.ld.signature.ecdsa;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.BigIntegers;

import com.apicatalog.ld.signature.KeyGenError;
import com.apicatalog.ld.signature.SigningError;
import com.apicatalog.ld.signature.VerificationError;
import com.apicatalog.ld.signature.VerificationError.Code;
import com.apicatalog.ld.signature.algorithm.SignatureAlgorithm;
import com.apicatalog.ld.signature.key.KeyPair;
import com.apicatalog.multikey.MultiKey;

final class BCECDSASignatureProvider implements SignatureAlgorithm {

    public enum CurveType {
        P256, P384, P512
    };

    private final CurveType curveType;

    public BCECDSASignatureProvider(CurveType curveType) {
        this.curveType = curveType;
    }

    protected String getSignatureName() {
        switch (curveType) {
        case P256:
            return "SHA256withECDSA";
        case P384:
            return "SHA384withECDSA";
        case P512:
            return "SHA512withECDSA";
        }
        throw new IllegalStateException();
    }

    @Override
    public void verify(final byte[] publicKey, final byte[] signature, final byte[] data) throws VerificationError {
        try {
            final Signature suite = Signature.getInstance(getSignatureName());

            suite.initVerify(getPublicKeyFromBytes(publicKey));

            suite.update(data);

            if (!suite.verify(toDerSignature(signature))) {
                throw new VerificationError(Code.InvalidSignature);
            }

        } catch (Exception e) {
            throw new VerificationError(Code.InvalidSignature, e);
        }
    }

    protected ExtendedDigest getDigestIstance() {
        switch (curveType) {
        case P256:
            return new SHA256Digest();
        case P384:
            return new SHA384Digest();
        case P512:
            return new SHA512Digest();
        }
        throw new IllegalStateException();
    }

    @Override
    public byte[] sign(final byte[] privateKey, final byte[] data) throws SigningError {

        try {

            final ExtendedDigest digest = getDigestIstance();

            final byte[] hash = new byte[digest.getByteLength()];
            digest.update(data, 0, data.length);
            digest.doFinal(hash, 0);

            final ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(getDigestIstance()));

            signer.init(true, getPrivateKeyFromBytes(privateKey));

            final BigInteger[] signature = signer.generateSignature(hash);

            final byte[] r = BigIntegers.asUnsignedByteArray(signature[0]);
            final byte[] s = BigIntegers.asUnsignedByteArray(signature[1]);

            final byte[] sigBytes = new byte[r.length + s.length];

            System.arraycopy(r, 0, sigBytes, 0, r.length);
            System.arraycopy(s, 0, sigBytes, r.length, s.length);

            return sigBytes;

        } catch (Exception e) {
            throw new SigningError(SigningError.Code.Internal, e);
        }
    }

    protected String getCurveName() {
        switch (curveType) {
        case P256:
            return "secp256r1";
        case P384:
            return "secp384r1";
        case P512:
            return "secp512r1";
        }
        throw new IllegalStateException();
    }

    @Override
    public KeyPair keygen() throws KeyGenError {

        try {

            final KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());

            generator.initialize(new ECGenParameterSpec(getCurveName()));

            final java.security.KeyPair keyPair = generator.genKeyPair();

            ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
            ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();

            ECPrivateKeyParameters privKeyParams = (ECPrivateKeyParameters) PrivateKeyFactory.createKey(privKey.getEncoded());
            final byte[] rawPrivKey = BigIntegers.asUnsignedByteArray(privKeyParams.getD());

            ECPublicKeyParameters pubKeyParams = (ECPublicKeyParameters) PublicKeyFactory
                    .createKey(pubKey.getEncoded());

            final byte[] rawKPubKey = pubKeyParams.getQ().getEncoded(true);

            final MultiKey multikey = new MultiKey();
            multikey.setAlgorithm(curveType.name());
            multikey.setPublicKey(rawKPubKey);
            multikey.setPrivateKey(rawPrivKey);
            return multikey;

        } catch (Exception e) {
            throw new KeyGenError(e);
        }
    }

    private PublicKey getPublicKeyFromBytes(final byte[] pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(getCurveName());
        final KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        final ECNamedCurveSpec params = new ECNamedCurveSpec(getCurveName(), spec.getCurve(), spec.getG(), spec.getN(), spec.getH());
        final ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKey);
        final ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        return (ECPublicKey) kf.generatePublic(pubKeySpec);
    }

    private ECPrivateKeyParameters getPrivateKeyFromBytes(final byte[] privKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(getCurveName());
        final ECDomainParameters ecParams = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH());
        return new ECPrivateKeyParameters(new BigInteger(1, privKey), ecParams);
    }

    private static byte[] toDerSignature(final byte[] signature) throws IOException {

        if (signature == null) {
            throw new IllegalArgumentException("'signature' parameter must not be null.");
        }
        if (signature.length != 64) {
            throw new IllegalArgumentException("'signature' must be exactly 64 bytes long.");
        }

        final byte[] rBytes = Arrays.copyOfRange(signature, 0, 32);
        final byte[] sBytes = Arrays.copyOfRange(signature, 32, 64);

        final BigInteger r = new BigInteger(1, rBytes);
        final BigInteger s = new BigInteger(1, sBytes);

        final DERSequence sequence = new DERSequence(new ASN1Encodable[] {
                new ASN1Integer(r),
                new ASN1Integer(s)
        });

        return sequence.getEncoded();
    }

//    public static void main(String[] args) {
//
//        try {
//            var pair = new BCECDSASignatureProvider(CurveType.P512).keygen();
//
//            var pub = Multibase.encode(Algorithm.Base58Btc,
//                    Multicodec.encode(Codec.P512PublicKey,
//                            pair.publicKey()));
//
//            var priv = Multibase.encode(Algorithm.Base58Btc,
//                    Multicodec.encode(Codec.P512PrivateKey,
//                            pair.privateKey()));
//
//            System.out.println("PUBLIC " + pub);
//            System.out.println("PRIVATE " + priv);
//
//        } catch (Exception ex) {
//            System.out.println(ex);
//        } catch (KeyGenError e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//    }
}
