package com.apicatalog.ld.signature.ed25519;

import java.net.URI;

import com.apicatalog.ld.signature.key.KeyPair;

public final class EdDSAKeyPair2022 extends EdDSAVerificationKey2022 implements KeyPair {

    private final byte[] privateKey;
    
    public EdDSAKeyPair2022(
                URI id,
                URI controller,
                URI type,
                byte[] publicKey,
                byte[] privateKey
                ) {
        super(id, controller, type, publicKey);
        this.privateKey = privateKey;
    }

    @Override
    public byte[] privateKey() {
        return privateKey;
    }
}
