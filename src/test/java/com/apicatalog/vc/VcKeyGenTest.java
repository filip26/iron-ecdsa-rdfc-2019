package com.apicatalog.vc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import com.apicatalog.ld.signature.KeyGenError;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multibase.Multibase.Algorithm;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.Multicodec.Codec;
import com.apicatalog.multicodec.Multicodec.Type;

@DisplayName("Keys Generation")
@TestMethodOrder(OrderAnnotation.class)
class VcKeyGenTest {

    @DisplayName("Data Integrity")
    @Order(1)
    @Disabled
    @Test
    void generate32L() throws KeyGenError {
        
//        ECDSA256SignatureProvider x = new ECDSA256SignatureProvider();
        
//        KeyPair y = x.keygen(256);
//        
//        System.out.println("1 " + y.id());
//        System.out.println("1 " + y.type());
//        System.out.println("1 " + y.publicKey().length);
//        System.out.println("1 " + y.privateKey().length);
//        
//        String  ppe = Multibase.encode(Algorithm.Base58Btc, Multicodec.encode(Codec.P256PublicKey, y.publicKey()));
//        String  pre = Multibase.encode(Algorithm.Base58Btc, Multicodec.encode(Codec.P256PrivateKey, y.privateKey()));
//        
//        System.out.println("public " + ppe);
//        System.out.println("private " + pre);
//        System.out.println("public " + ppe.length());
//        System.out.println("private " + pre.length());
//        
////        KeyPair kp = Vc.generateKeys("https://w3id.org/security#Ed25519KeyPair2020").get(URI.create("urn:1"), 256);
////        assertNotNull(kp);
////        assertEquals("urn:1", kp.id());
////        assertEquals("https://w3id.org/security#Ed25519KeyPair2020", kp.type());
////        assertNotNull(kp.publicKey());
////        assertNotNull(kp.privateKey());
////        assertEquals(32, kp.publicKey().length);
////        assertEquals(32, kp.privateKey().length);
//        
//        for (Provider provider : Security.getProviders()) {
//            System.out.println(provider.getName());
//            for (Service service : provider.getServices()) {
//                if (service.getType().equals("KeyFactory"))
//                    System.out.println("  " + service.getAlgorithm());
//            }
//        }
//        
    }
    
    public static void main(String[] args) {
        
        var x = Multibase.decode("zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP");
        var y = Multicodec.decode(Type.Key, x);
        System.out.println(Multicodec.codec(Type.Key, x));
        var z = Multicodec.encode(Codec.P256PublicKey, y);
        System.out.println(Multicodec.codec(Type.Key, z));
        var a = Multibase.encode(Algorithm.Base58Btc, z);
        
        System.out.println(a);
        
        
    }
    
}
