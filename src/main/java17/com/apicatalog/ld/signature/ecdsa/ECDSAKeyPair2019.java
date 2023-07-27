package com.apicatalog.ld.signature.ecdsa;

import java.net.URI;

import com.apicatalog.ld.signature.key.KeyPair;

/*TODO replace with Multikey */
@Deprecated
public record ECDSAKeyPair2019(
        URI id,
        URI controller,
        URI type,
        byte[] publicKey,
        byte[] privateKey
        ) implements KeyPair {

    public ECDSAKeyPair2019 {
//        Objects.requireNonNull(id);
    }
}
