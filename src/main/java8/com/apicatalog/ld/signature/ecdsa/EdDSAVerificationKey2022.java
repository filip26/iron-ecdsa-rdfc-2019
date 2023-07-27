package com.apicatalog.ld.signature.ed25519;

import java.net.URI;

import com.apicatalog.ld.signature.key.VerificationKey;

public class EdDSAVerificationKey2022 implements VerificationKey {

    private final URI id;
    private final URI controller;
    private final URI type;
    private final byte[] publicKey;
    
    public EdDSAVerificationKey2022(
            URI id,
            URI controller,
            URI type,
            byte[] publicKey
            )  {
        this.id = id;
        this.controller = controller;
        this.type = type;
        this.publicKey = publicKey;
    }
    
    @Override
    public byte[] publicKey() {
        return publicKey;
    }

    @Override
    public URI id() {
        return id;
    }

    @Override
    public URI type() {
        return type;
    }

    @Override
    public URI controller() {
        return controller;
    }
}
