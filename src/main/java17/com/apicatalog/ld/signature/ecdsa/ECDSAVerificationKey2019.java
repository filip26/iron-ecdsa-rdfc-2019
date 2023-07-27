package com.apicatalog.ld.signature.ecdsa;

import java.net.URI;
import java.util.Objects;

import com.apicatalog.ld.signature.key.VerificationKey;

/*TODO replace with Multikey */
@Deprecated
public record ECDSAVerificationKey2019(
        URI id,
        URI controller,
        URI type,
        byte[] publicKey
        ) implements VerificationKey {

    public ECDSAVerificationKey2019 {
        Objects.requireNonNull(id);
    }
}
