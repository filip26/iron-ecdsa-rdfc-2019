package com.apicatalog.ld.signature.ecdsa;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

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

            var r = toUnsignedArray(signature[0]);
            var s = toUnsignedArray(signature[1]);

            System.arraycopy(r, 0, sigBytes, 0, 32);
            System.arraycopy(s, 0, sigBytes, 32, 32);

            return sigBytes;

        } catch (Exception e) {
            throw new SigningError(SigningError.Code.Internal, e);
        }
    }

    @Override
    public KeyPair keygen() throws KeyGenError {

        return null;
//        try {
//            SignatureConfig.register();
//            KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
//
//            byte[] privateKey = extractKey(handle);
//            byte[] publicKey = extractKey(handle.getPublicKeysetHandle());
//            
//            System.out.println("public " + Arrays.toString(publicKey));
//            System.out.println("private " + Arrays.toString(privateKey));
//            
////            handle.
////            
////            try (FileOutputStream outputStream = new FileOutputStream(keyFile)) {
////                CleartextKeysetHandle.write(handle, JsonKeysetWriter.withOutputStream(outputStream));
////              }
//            return new ECDSAKeyPair2019(
//                            null,
//                            null,
//                            URI.create(ECDSASignature2019.KEY_PAIR_TYPE.uri()),
//                            publicKey,
//                            privateKey
//                        );

//        } catch (IOException | GeneralSecurityException e) {
//            throw new KeyGenError(e);
//        }
    }

    // {"primaryKeyId":236535046,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.EcdsaPublicKey","value":"EgYIAxACGAIaIG3K2hTQfWh39VaMtsqjv96Ko97wvPUsisu7PFUCW2w+IiEApC5XlM9t5AKpFTuHXGMSWneec3WyTXnN5ROfxMt7h5U=","keyMaterialType":"ASYMMETRIC_PUBLIC"},"status":"ENABLED","keyId":236535046,"outputPrefixType":"TINK"}]}
    // {"primaryKeyId":236535046,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.EcdsaPrivateKey","value":"Ek0SBggDEAIYAhogbcraFNB9aHf1Voy2yqO/3oqj3vC89SyKy7s8VQJbbD4iIQCkLleUz23kAqkVO4dcYxJad55zdbJNec3lE5/Ey3uHlRogE97+vw/vNSGnP3/Sdxxz+rRMWArQs0j1EtoSwmt3i0k=","keyMaterialType":"ASYMMETRIC_PRIVATE"},"status":"ENABLED","keyId":236535046,"outputPrefixType":"TINK"}]}

//    private static byte[] extractKey(KeysetHandle handle) throws IOException {
//
//        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//        
//        
////      ObjectOutputStream o = new ObjectOutputStream(outputStream);
////      BinaryKeysetWriter.withFile(outputStream);
//
//      CleartextKeysetHandle.write(handle, JsonKeysetWriter.withOutputStream(outputStream));
////      o.close();
//      
//       JsonReader reader = Json.createReader(new ByteArrayInputStream(outputStream.toByteArray()));
//      
//       
//       
//       JsonObject tinkKeySet = reader.readObject();
//       
//       String base64PrivateKey = tinkKeySet.getJsonArray("key").getJsonObject(0).getJsonObject("keyData")
//       .getString("value");
//       
////      CleartextKeysetHandle.write(handle, BinaryKeysetWriter.withOutputStream(outputStream));
//       System.out.println("\n"+ new String(outputStream.toByteArray()));
//      System.out.println("\n"+ base64PrivateKey);
//      
//      return Base64.getDecoder().decode(base64PrivateKey.getBytes());
//        
//    }

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

    public static byte[] toUnsignedArray(final BigInteger b) {
        byte[] array = b.toByteArray();
        if (array[0] == 0) {
            byte[] tmp = new byte[array.length - 1];
            System.arraycopy(array, 1, tmp, 0, tmp.length);
            array = tmp;
        }
        return array;
    }

    public static PublicKey genXXXXEcPubKey(byte[] key) throws Exception {

        AlgorithmParameters a = AlgorithmParameters.getInstance("EC");
        a.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec p = a.getParameterSpec(ECParameterSpec.class);

//        BigInteger s = new BigInteger(1, /*byte[32] privatekey value*/);
        BigInteger s = new BigInteger(1, key);
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey kp = kf.generatePublic(new ECPrivateKeySpec(s, p));

        return kp;
//        KeyFactory factory = KeyFactory.getInstance("ECDSA", "BC");
//        java.security.PublicKey ecPublicKey = (ECPublicKey) factory
//                .generatePublic(new X509EncodedKeySpec(key));
//        return (ECPublicKey) ecPublicKey;
    }

    public static PrivateKey genEcPrivKey(byte[] key) throws Exception {

        AlgorithmParameters a = AlgorithmParameters.getInstance("EC");
        a.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec p = a.getParameterSpec(ECParameterSpec.class);

//        BigInteger s = new BigInteger(1, /*byte[32] privatekey value*/);
        BigInteger s = new BigInteger(1, key);
        KeyFactory kf = KeyFactory.getInstance("EC");
        PrivateKey kp = kf.generatePrivate(new ECPrivateKeySpec(s, p));

        return kp;
        // castable to ECPrivateKey if desired/needed
////        KeyFactory factory = KeyFactory.getInstance("ECDSA", "BC");
//        KeyFactory factory = KeyFactory.getInstance("EC");
//        java.security.PrivateKey ecPublicKey = (ECPrivateKey) factory
//                .generatePrivate(new PKCS8EncodedKeySpec(key));
//        return (ECPrivateKey) ecPublicKey;
    }

    public static void main(String[] args) {
        System.out.println("Java Version: " + getJavaVersion());
        try {
            KeyPairGenerator kpg;
            kpg = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecsp;
            ecsp = new ECGenParameterSpec("secp256r1");
//              ecsp = new ECGenParameterSpec("P-256");
            kpg.initialize(ecsp);

            java.security.KeyPair kp = kpg.genKeyPair();
            PrivateKey privKey = kp.getPrivate();
            PublicKey pubKey = kp.getPublic();

            System.out.println(privKey.getFormat());
            System.out.println(privKey.toString());
            System.out.println(privKey.getFormat());
            System.out.println(pubKey.toString());

            var pub = Multibase.encode(Algorithm.Base58Btc,

                    Multicodec.encode(Codec.P256PublicKey,
                            pubKey.getEncoded()));

            System.out.println("PUBLIC ENCODED " + pub);

            var priv = Multibase.encode(Algorithm.Base58Btc,

                    Multicodec.encode(Codec.P256PrivateKey,
                            privKey.getEncoded()));
            System.out.println("PRIVATE ENCODED " + priv);

        } catch (Exception ex) {
            System.out.println(ex);
        }
    }

    public static String getJavaVersion() {
        String[] javaVersionElements = System.getProperty("java.runtime.version").split("\\.|_|-b");
        String main = "", major = "", minor = "", update = "", build = "";
        int elementsSize = javaVersionElements.length;
        if (elementsSize > 0) {
            main = javaVersionElements[0];
        }
        if (elementsSize > 1) {
            major = javaVersionElements[1];
        }
        if (elementsSize > 2) {
            minor = javaVersionElements[2];
        }
        if (elementsSize > 3) {
            update = javaVersionElements[3];
        }
        if (elementsSize > 4) {
            build = javaVersionElements[4];
        }
        return "main: " + main + " major: " + major + " minor: " + minor + " update: " + update + " build: " + build;
    }

}
