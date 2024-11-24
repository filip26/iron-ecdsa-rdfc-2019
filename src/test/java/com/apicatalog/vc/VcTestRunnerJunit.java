package com.apicatalog.vc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import com.apicatalog.controller.key.KeyPair;
import com.apicatalog.cryptosuite.SigningError;
import com.apicatalog.cryptosuite.VerificationError;
import com.apicatalog.did.key.DidKey;
import com.apicatalog.did.key.DidKeyResolver;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.json.JsonLdComparison;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.jsonld.loader.SchemeRouter;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.signature.ecdsa.ECDSASignature2019;
import com.apicatalog.linkedtree.adapter.NodeAdapterError;
import com.apicatalog.linkedtree.builder.TreeBuilderError;
import com.apicatalog.linkedtree.jsonld.io.JsonLdReader;
import com.apicatalog.linkedtree.orm.mapper.TreeReaderMapping;
import com.apicatalog.multikey.Multikey;
import com.apicatalog.vc.issuer.Issuer;
import com.apicatalog.vc.loader.StaticContextLoader;
import com.apicatalog.vc.method.resolver.ControllableKeyProvider;
import com.apicatalog.vc.method.resolver.MethodPredicate;
import com.apicatalog.vc.method.resolver.MethodSelector;
import com.apicatalog.vc.method.resolver.RemoteMultikeyProvider;
import com.apicatalog.vc.method.resolver.VerificationKeyProvider;
import com.apicatalog.vc.verifier.Verifier;
import com.apicatalog.vcdi.DataIntegrityProofDraft;
import com.apicatalog.vcdi.VcdiVocab;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;
import jakarta.json.JsonWriter;
import jakarta.json.JsonWriterFactory;
import jakarta.json.stream.JsonGenerator;

public class VcTestRunnerJunit {

    private final VcTestCase testCase;

    public final static DocumentLoader LOADER = new StaticContextLoader(
            new UriBaseRewriter(
                    VcTestCase.BASE,
                    "classpath:",
                    new SchemeRouter().set("classpath", new ClasspathLoader())));

    final static VerificationKeyProvider RESOLVERS = defaultResolvers(LOADER);

    public final static ECDSASignature2019 SUITE = new ECDSASignature2019();

    public final Verifier VERIFIER = Verifier.with(SUITE)
            .methodResolver(RESOLVERS)
            .loader(LOADER);

    public VcTestRunnerJunit(VcTestCase testCase) {
        this.testCase = testCase;
    }

    public void execute() {

        assertNotNull(testCase.type);
        assertNotNull(testCase.input);

        try {
            if (testCase.type.contains(VcTestCase.vocab("VeriferTest"))) {

                final Map<String, Object> params = new HashMap<>();
                params.put(VcdiVocab.DOMAIN.name(), testCase.domain);
                params.put(VcdiVocab.CHALLENGE.name(), testCase.challenge);
                params.put(VcdiVocab.PURPOSE.name(), testCase.purpose);
                params.put(VcdiVocab.NONCE.name(), testCase.nonce);

                final Verifiable verifiable = VERIFIER.verify(testCase.input, params);

                assertNotNull(verifiable);
                assertFalse(isNegative(), "Expected error " + testCase.result);

            } else if (testCase.type.contains(VcTestCase.vocab("IssuerTest"))) {

                assertNotNull(testCase.result);

                URI keyPairLocation = testCase.keyPair;

                if (keyPairLocation == null) {
                    // set dummy key pair
                    keyPairLocation = URI.create(VcTestCase.base("issuer/0001-keys.json"));
                }

                Issuer issuer = SUITE.createIssuer(getKeys(keyPairLocation, LOADER))
                        .loader(LOADER);

                // proof options
                DataIntegrityProofDraft draft = issuer.createDraft(testCase.verificationMethod);

                draft.purpose(URI.create("https://w3id.org/security#assertionMethod"));
                draft.created(testCase.created);
                draft.domain(testCase.domain);
                draft.challenge(testCase.challenge);
                draft.nonce(testCase.nonce);

                final JsonObject issued = issuer.sign(testCase.input, draft);

                assertNotNull(issued);

                assertFalse(isNegative(), "Expected error " + testCase.result);

                final Document expected = LOADER.loadDocument(URI.create((String) testCase.result),
                        new DocumentLoaderOptions());

                boolean match = JsonLdComparison.equals(
                        issued,
                        expected.getJsonContent().orElse(null));

                if (!match) {

                    write(testCase, issued, expected.getJsonContent().orElse(null));

                    fail("Expected result does not match");
                }

            } else {
                fail("Unknown test execution method: " + testCase.type);
                return;
            }

            if (testCase.type.stream().noneMatch(o -> o.endsWith("PositiveEvaluationTest"))) {
                fail();
                return;
            }

        } catch (VerificationError e) {
            assertException(e.verificationErrorCode() != null ? e.verificationErrorCode().name() : null, e);

        } catch (SigningError e) {
            assertException(e.signatureErrorCode() != null ? e.signatureErrorCode().name() : null, e);

        } catch (DocumentError e) {
            assertException(e.code(), e);

        } catch (JsonLdError e) {
            e.printStackTrace();
            fail(e);

        } catch (Exception e) {
            assertException(e.getClass().getSimpleName(), e);
        }
    }

    final void assertException(final String code, Throwable e) {

        if (!isNegative()) {
            e.printStackTrace();
            fail(e.getMessage(), e);
            return;
        }

        if (!Objects.equals(testCase.result, code)) {
            e.printStackTrace();
        }

        // compare expected exception
        assertEquals(testCase.result, code);
    }

    final boolean isNegative() {
        return testCase.type.stream().anyMatch(o -> o.endsWith("NegativeEvaluationTest"));
    }

    public static void write(final VcTestCase testCase, final JsonStructure result,
            final JsonStructure expected) {
        final StringWriter stringWriter = new StringWriter();

        try (final PrintWriter writer = new PrintWriter(stringWriter)) {
            writer.println("Test " + testCase.id + ": " + testCase.name);

            final JsonWriterFactory writerFactory = Json.createWriterFactory(
                    Collections.singletonMap(JsonGenerator.PRETTY_PRINTING, true));

            if (expected != null) {
                write(writer, writerFactory, "Expected", expected);
                writer.println();
            }

            if (result != null) {
                write(writer, writerFactory, "Actual", result);
                writer.println();
            }
        }

        System.out.println(stringWriter.toString());
    }

    static final void write(final PrintWriter writer, final JsonWriterFactory writerFactory,
            final String name, final JsonValue result) {

        writer.println(name + ":");

        final StringWriter out = new StringWriter();

        try (final JsonWriter jsonWriter = writerFactory.createWriter(out)) {
            jsonWriter.write(result);
        }

        writer.write(out.toString());
        writer.println();
    }

    static final KeyPair getKeys(final URI keyPairLocation, final DocumentLoader loader)
            throws DocumentError, JsonLdError, TreeBuilderError, NodeAdapterError {

        final JsonObject keys = loader.loadDocument(keyPairLocation, new DocumentLoaderOptions()).getJsonContent().map(JsonStructure::asJsonObject).orElseThrow();

        JsonLdReader reader = JsonLdReader.of(TreeReaderMapping.createBuilder()
                .scan(Multikey.class).build(), loader);

        return reader.read(Multikey.class, keys);
    }

    static final VerificationKeyProvider defaultResolvers(DocumentLoader loader) {

        return MethodSelector.create()
                .with(MethodPredicate.methodId(
                        // accept only remote Multikey
                        m -> m.getScheme().equalsIgnoreCase("https")),
                        new RemoteMultikeyProvider(loader))

                // accept did:key
                .with(MethodPredicate.methodId(DidKey::isDidKeyUrl),
                        ControllableKeyProvider.of(new DidKeyResolver(ECDSASignature2019.CODECS)))

                .build();
    }

}
