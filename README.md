# Iron ECDSA RDFC 2019 Signature Suite

An implementation of the [W3C ECDSA RDFC 2019](https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-rdfc-2019) in Java.

[![Java 17 CI](https://github.com/filip26/iron-ecdsa-rdfc-2019/actions/workflows/java17-build.yml/badge.svg)](https://github.com/filip26/iron-ecdsa-rdfc-2019/actions/workflows/java17-build.yml)
[![Android (Java 8) CI](https://github.com/filip26/iron-ecdsa-rdfc-2019/actions/workflows/java8-build.yml/badge.svg)](https://github.com/filip26/iron-ecdsa-rdfc-2019/actions/workflows/java8-build.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/814313b9677e4c8baff7d56bcfe572e6)](https://app.codacy.com/gh/filip26/iron-ecdsa-rdfc-2019/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/814313b9677e4c8baff7d56bcfe572e6)](https://app.codacy.com/gh/filip26/iron-ecdsa-rdfc-2019/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)
[![Maven Central](https://img.shields.io/maven-central/v/com.apicatalog/iron-ecdsa-rdfc-2019.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:com.apicatalog%20AND%20a:iron-ecdsa-rdfc-2019)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Features
* [W3C ECDSA Signature 2019](https://www.w3.org/TR/vc-di-ecdsa/)
  * Verifier, Issuer,
  * Key pair generator
  * P-256 (secp256r1), P-384 (secp384r1)
* [VC HTTP API & Service](https://github.com/filip26/iron-vc-api)

## Installation

### Maven
Java 17+

```xml
<dependency>
    <groupId>com.apicatalog</groupId>
    <artifactId>iron-ecdsa-rdfc-2019</artifactId>
    <version>0.14.0</version>
</dependency>

<dependency>
    <groupId>com.apicatalog</groupId>
    <artifactId>iron-verifiable-credentials</artifactId>
    <version>0.14.0</version>
</dependency>
```

### Gradle

Android 12+ (API Level 31+)

```gradle
implementation("com.apicatalog:iron-ecdsa-rdfc-2019-jre8:0.14.0")
implementation("com.apicatalog:iron-verifiable-credentials-jre8:0.14.0")
```

## Usage

### Verifier

```javascript
// create a new verifier instance
static Verifier VERIFIER = Verifier.with(new ECDSASignature2019())
    // options
    .loader(...)
    .statusValidator(...)
    .subjectValidator(...);

try {
  // verify the given input proof(s)
  var verifiable = VERIFIER.verify(credential|presentation);
  
  // or with runtime parameters e.g. domain, challenge, etc.
  var verifiable = VERIFIER.verify(credential|presentation, parameters);
  
  // get verified details
  verifiable.subject()
  verifiable.id()
  verifiable.type()
  // ...
  
} catch (VerificationError | DocumentError e) {
  ...
}

```

### Issuer

```javascript

// create a signature suite static instance
static SignatureSuite SUITE = new ECDSASignature2019();

// create a new issuer instance
Issuer ISSUER = SUITE.createIssuer(keyPairProvider)
  // options
  .loader(...);
    
try {
  // create a new proof draft using P-256
  var proofDraft = SUITE.createP256Draft(verificationMethod, purpose);
  // or P-384
  var proofDraft = SUITE.createP384Draft(verificationMethod, purpose);
  
  // set custom options
  proofDraft.created(...);
  proofDraft.domain(...);
  ...

  // issue a new verifiable, i.e. sign the input and add a new proof
  var verifiable = ISSUER.sign(credential|presentation, proofDraft).compacted();
  
} catch (SigningError | DocumentError e) {
  ...
}

```

## Documentation

[![javadoc](https://javadoc.io/badge2/com.apicatalog/iron-ecdsa-rdfc-2019/javadoc.svg)](https://javadoc.io/doc/com.apicatalog/iron-ecdsa-rdfc-2019)

## Contributing

All PR's welcome!

### Building

Fork and clone the project repository.

#### Java 17
```bash
> cd iron-ecdsa-rdfc-2019
> mvn clean package
```

#### Java 8
```bash
> cd iron-ecdsa-rdfc-2019
> mvn -f pom_jre8.xml clean package
```

## Resources
* [W3C ECDSA RDFC 2019](https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-rdfc-2019)
* [Iron Verifiable Credentials](https://github.com/filip26/iron-verifiable-credentials)

## Sponsors

<a href="https://github.com/digitalbazaar">
  <img src="https://avatars.githubusercontent.com/u/167436?s=200&v=4" width="40" />
</a> 

## Commercial Support
Commercial support is available at filip26@gmail.com

