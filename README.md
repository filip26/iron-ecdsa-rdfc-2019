# Iron ECDSA Signature Suite 2019

An implementation of the [ECDSA Cryptosuite 2022](https://www.w3.org/TR/vc-di-ecdsa/) in Java.

[![Java 17 CI](https://github.com/filip26/iron-ecdsa-cryptosuite-2019/actions/workflows/java17-build.yml/badge.svg)](https://github.com/filip26/iron-ecdsa-cryptosuite-2019/actions/workflows/java17-build.yml)
[![Android (Java 8) CI](https://github.com/filip26/iron-ecdsa-cryptosuite-2019/actions/workflows/java8-build.yml/badge.svg)](https://github.com/filip26/iron-ecdsa-cryptosuite-2019/actions/workflows/java8-build.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/806688cdb1d248e8b5cc2a67f6c2f0f8)](https://www.codacy.com/gh/filip26/iron-ecdsa-cryptosuite-2019/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=filip26/iron-ecdsa-cryptosuite-2019&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/806688cdb1d248e8b5cc2a67f6c2f0f8)](https://www.codacy.com/gh/filip26/iron-ecdsa-cryptosuite-2019/dashboard?utm_source=github.com&utm_medium=referral&utm_content=filip26/iron-ecdsa-cryptosuite-2019&utm_campaign=Badge_Coverage)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=filip26_iron-ecdsa-cryptosuite-2019&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=filip26_iron-ecdsa-cryptosuite-2019)
[![Maven Central](https://img.shields.io/maven-central/v/com.apicatalog/iron-ecdsa-cryptosuite-2019.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22com.apicatalog%22%20AND%20a:%22iron-ecdsa-cryptosuite-2019%22)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Features
* [ECDSA Signature 2019](https://www.w3.org/TR/vc-di-ecdsa/)
  * Verifying VC/VP
  * Issuing VC/VP
  * Key pair generator
  * P-256 (secp256r1), P-384 (secp384r1)
* [VC HTTP API & Service](https://github.com/filip26/iron-vc-api)

## Installation

### Maven
Java 17+

```xml
<dependency>
    <groupId>com.apicatalog</groupId>
    <artifactId>iron-ecdsa-cryptosuite-2019</artifactId>
    <version>0.9.0</version>
</dependency>

<dependency>
    <groupId>com.apicatalog</groupId>
    <artifactId>iron-verifiable-credentials</artifactId>
    <version>0.9.0</version>
</dependency>
```

### Gradle

Android 12+ (API Level 31+)

```gradle
compile group: 'com.apicatalog', name: 'iron-ecdsa-cryptosuite-2019-jre8', version: '0.9.0'
compile group: 'com.apicatalog', name: 'iron-verifiable-credentials-jre8', version: '0.9.0'
```

## Documentation

[![javadoc](https://javadoc.io/badge2/com.apicatalog/iron-ecdsa-cryptosuite-2019/javadoc.svg)](https://javadoc.io/doc/com.apicatalog/iron-ecdsa-cryptosuite-2019)

## Usage

### Verifying 

```java
try {
  Vc.verify(credential|presentation, new ECDSASignature2019())
      
    // optional
    .base(...)
    .loader(documentLoader) 
    .statusVerifier(...)
    .useBundledContexts(true|false)

    // custom | suite specific | parameters
    .param(DataIntegrity.DOMAIN.name(), ....)

    // assert document validity
    .isValid();
    
} catch (VerificationError | DataError e) {
  ...
}

```

### Issuing

```java
var suite = new ECDSASignature2019();

var proofDraft = suite.createP256Draft(
    verificationMethod,
    purpose,
    created,
    // optional
    domain,
    challenge
    );

Vc.sign(credential|presentation, keys, proofDraft)

   // optional
   .base(...)
   .loader(documentLoader) 
   .statusVerifier(...)
   .useBundledContexts(true|false)

    // return signed document in a compacted form
   .getCompacted();

```

## Contributing

All PR's welcome!

### Building

Fork and clone the project repository.

#### Java 17
```bash
> cd iron-ecdsa-cryptosuite-2019
> mvn clean package
```

#### Java 8
```bash
> cd iron-ecdsa-cryptosuite-2019
> mvn -f pom_jre8.xml clean package
```

## Resources
* [ECDSA Cryptosuite 2019](https://www.w3.org/TR/vc-di-ecdsa/)
* [Interoperability Report](https://w3c.github.io/vc-di-ecdsa-test-suite/)
* [Iron Verifiable Credentials](https://github.com/filip26/iron-verifiable-credentials)

## Sponsors

<a href="https://github.com/digitalbazaar">
  <img src="https://avatars.githubusercontent.com/u/167436?s=200&v=4" width="40" />
</a> 

## Commercial Support
Commercial support is available at filip26@gmail.com
.
