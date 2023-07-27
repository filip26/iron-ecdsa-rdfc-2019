package com.apicatalog.ld.signature.ecdsa;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
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
import org.bouncycastle.crypto.digests.SHA256Digest;
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
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multibase.Multibase.Algorithm;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.Multicodec.Codec;

public final class ECDSA256SignatureProvider implements SignatureAlgorithm {

    @Override
    public void verify(byte[] publicKey, byte[] signature, byte[] data) throws VerificationError {
        try {
            final Signature suite = Signature.getInstance("SHA256withECDSA");

            suite.initVerify(getPublicKeyFromBytes(publicKey));

            suite.update(data);

            if (!suite.verify(toDerSignature(signature))) {
                throw new VerificationError(Code.InvalidSignature);
            }

        } catch (Exception e) {
            throw new VerificationError(Code.InvalidSignature, e);
        }
    }

    @Override
    public byte[] sign(byte[] privateKey, byte[] data) throws SigningError {

        try {

            final SHA256Digest digest = new SHA256Digest();

            final byte[] hash = new byte[digest.getByteLength()];
            digest.update(data, 0, data.length);
            digest.doFinal(hash, 0);

            final ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));

            signer.init(true, getPrivateKeyFromBytes(privateKey));

            var signature = signer.generateSignature(hash);

            byte[] sigBytes = new byte[64];

            var r = BigIntegers.asUnsignedByteArray(signature[0]);
            var s = BigIntegers.asUnsignedByteArray(signature[1]);

            System.arraycopy(r, 0, sigBytes, 0, 32);
            System.arraycopy(s, 0, sigBytes, 32, 32);

            return sigBytes;

        } catch (Exception e) {
            throw new SigningError(SigningError.Code.Internal, e);
        }
    }

    @Override
    public KeyPair keygen() throws KeyGenError {

        try {
            
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());

            generator.initialize(new ECGenParameterSpec("secp256r1"));

            final java.security.KeyPair keyPair = generator.genKeyPair();

            ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
            ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();

            ECPrivateKeyParameters privKeyParams = (ECPrivateKeyParameters) PrivateKeyFactory.createKey(privKey.getEncoded());
            final byte[] rawPrivKey = BigIntegers.asUnsignedByteArray(privKeyParams.getD());

            ECPublicKeyParameters pubKeyParams = (ECPublicKeyParameters) PublicKeyFactory
                    .createKey(pubKey.getEncoded());
            final byte[] rawKPubKey = pubKeyParams.getQ().getEncoded(true);

            return new ECDSAKeyPair2019(
                            null,
                            null,
                            URI.create(ECDSASignature2019.KEY_PAIR_TYPE.uri()),
                            rawKPubKey,
                            rawPrivKey
                        );

        } catch (Exception e) {
            throw new KeyGenError(e);
        }
    }

    private static PublicKey getPublicKeyFromBytes(byte[] pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", spec.getCurve(), spec.getG(), spec.getN(), spec.getH());
        ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKey);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
        return pk;
    }

    private static ECPrivateKeyParameters getPrivateKeyFromBytes(byte[] privKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECDomainParameters ecParams = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH());
        ECPrivateKeyParameters pk = new ECPrivateKeyParameters(new BigInteger(1, privKey), ecParams);
        return pk;
    }

    private static byte[] toDerSignature(byte[] signature) throws IOException {

        byte[] rBytes = Arrays.copyOfRange(signature, 0, 32);
        byte[] sBytes = Arrays.copyOfRange(signature, 32, 64);

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        DERSequence sequence = new DERSequence(new ASN1Encodable[] {
                new ASN1Integer(r),
                new ASN1Integer(s)
        });

        return sequence.getEncoded();
    }

    public static void main(String[] args) {

        try {
            var pair = new ECDSA256SignatureProvider().keygen();
            
            var pub = Multibase.encode(Algorithm.Base58Btc,
                    Multicodec.encode(Codec.P256PublicKey,
                            pair.publicKey()));

            var priv = Multibase.encode(Algorithm.Base58Btc,
                    Multicodec.encode(Codec.P256PrivateKey,
                            pair.privateKey()));

            System.out.println("PUBLIC " + pub);
            System.out.println("PRIVATE " + priv);

        } catch (Exception ex) {
            System.out.println(ex);
        } catch (KeyGenError e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
