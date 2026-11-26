package com.apisecurity.monitor.anomaly.payload.service;

import com.apisecurity.monitor.anomaly.payload.config.QueryPayloadDetectionProperties;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.InputLocation;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.SignatureIdentifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

class JsonRequestBodyPayloadInspectorTest {

    private QueryPayloadDetectionProperties properties;
    private JsonRequestBodyPayloadInspector inspector;

    @BeforeEach
    void setUp() {
        properties = new QueryPayloadDetectionProperties();
        PayloadSignatureDetector detector = new PayloadSignatureDetector(properties);
        inspector = new JsonRequestBodyPayloadInspector(properties, detector, new ObjectMapper());
    }

    @Test
    void detectsSuspiciousNestedStringValuesAndIgnoresNormalValues() {
        List<PayloadDetectionFinding> findings = inspect("""
                {"name":"Ada","comment":"<script>alert(1)</script>",
                 "nested":{"filter":"' OR '1'='1"}}
                """);

        assertThat(findings)
                .extracting(PayloadDetectionFinding::inputLocation, PayloadDetectionFinding::signatureIdentifier)
                .containsExactly(
                        tuple(InputLocation.REQUEST_BODY, SignatureIdentifier.XSS_SCRIPT_TAG),
                        tuple(InputLocation.REQUEST_BODY, SignatureIdentifier.SQLI_BOOLEAN_TAUTOLOGY));
    }

    @Test
    void ignoresBenignProgrammingRelatedJsonText() {
        assertThat(inspect("""
                {"language":"JavaScript: advanced patterns",
                 "lesson":"SQL UNION SELECT tutorial",
                 "document":"script documentation"}
                """)).isEmpty();
    }

    @Test
    void skipsSensitiveFieldsAndTheirEntireSubtrees() {
        List<PayloadDetectionFinding> findings = inspect("""
                {"password":"<script>alert(1)</script>",
                 "access_token":"' OR '1'='1",
                 "secret":{"nested":"<script>alert(1)</script>"},
                 "authorization":{"value":"1 UNION SELECT password"},
                 "API_KEY_VALUE":{"nested":"<script>alert(1)</script>"},
                 "Private-Key-Pem":"1 UNION SELECT password",
                 "auth":{"nested":"<script>alert(1)</script>"},
                 "AUTH_ENTICATION":"1 UNION SELECT password",
                 "emailVerificationToken":{"value":"<script>alert(1)</script>"},
                 "passwordConfirmation":"1 UNION SELECT password",
                 "comment":"normal text"}
                """);

        assertThat(findings).isEmpty();
    }

    @Test
    void decodesJsonUnicodeEscapesBeforeInspection() {
        assertThat(inspect("{\"comment\":\"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\"}"))
                .extracting(PayloadDetectionFinding::signatureIdentifier)
                .containsExactly(SignatureIdentifier.XSS_SCRIPT_TAG);
    }

    @Test
    void malformedJsonDiscardsProvisionalFindings() {
        assertThat(inspect("{\"comment\":\"<script>\"," )).isEmpty();
        assertThat(inspect("{\"comment\":\"<script>\"} {\"second\":true}" )).isEmpty();
    }

    @Test
    void invalidUtf8IsNotInspected() {
        assertThat(inspector.inspect(new byte[]{(byte) 0xc3, (byte) 0x28})).isEmpty();
    }

    @Test
    void ordinaryFieldsThatResembleAuthenticationNamesRemainInspectable() {
        assertThat(inspect("""
                {"author":"<script>alert(1)</script>",
                 "authority":"1 UNION SELECT password",
                 "authenticationMode":"<img src=x onerror=alert(1)>",
                 "apiKeynote":"javascript:alert(1)",
                 "privateKeyboardLayout":"' OR '1'='1"}
                """))
                .extracting(PayloadDetectionFinding::signatureIdentifier)
                .containsExactly(
                        SignatureIdentifier.XSS_SCRIPT_TAG,
                        SignatureIdentifier.SQLI_UNION_SELECT,
                        SignatureIdentifier.XSS_EVENT_HANDLER,
                        SignatureIdentifier.XSS_JAVASCRIPT_URI,
                        SignatureIdentifier.SQLI_BOOLEAN_TAUTOLOGY);
    }

    @Test
    void preservesFindingsCollectedBeforeOversizedValues() {
        properties.setMaxJsonStringLength(16);

        assertThat(inspect("""
                {"comment":"<script>",
                 "largeValue":"this value is intentionally longer than sixteen characters"}
                """))
                .extracting(PayloadDetectionFinding::signatureIdentifier)
                .containsExactly(SignatureIdentifier.XSS_SCRIPT_TAG);
    }

    @Test
    void preservesFindingsWhenTheInspectionValueBudgetIsExhausted() {
        properties.setMaxJsonValues(1);

        assertThat(inspect("{\"comment\":\"<script>\",\"ignored\":\"' OR '1'='1\"}"))
                .extracting(PayloadDetectionFinding::signatureIdentifier)
                .containsExactly(SignatureIdentifier.XSS_SCRIPT_TAG);
    }

    @Test
    void skipsExcessiveNestingButPreservesFindingsWithinTheDepthBudget() {
        properties.setMaxJsonDepth(1);

        assertThat(inspect("""
                {"comment":"<script>",
                 "nested":{"ignored":"' OR '1'='1"},
                 "second":"javascript:alert(1)"}
                """))
                .extracting(PayloadDetectionFinding::signatureIdentifier)
                .containsExactly(
                        SignatureIdentifier.XSS_SCRIPT_TAG,
                        SignatureIdentifier.XSS_JAVASCRIPT_URI);
    }

    @Test
    void malformedTrailingJsonStillDiscardsFindingsAfterBudgetExhaustion() {
        properties.setMaxJsonValues(1);

        assertThat(inspect("{\"comment\":\"<script>\",\"ignored\":\"safe\"} trailing"))
                .isEmpty();
    }

    @Test
    void oversizedAndDisabledBodiesReturnImmutableEmptyResults() {
        assertThat(properties.getMaxBodyCacheBytes()).isEqualTo(16_384);
        assertThatThrownBy(() -> properties.setMaxBodyCacheBytes(65_537))
                .isInstanceOf(IllegalArgumentException.class);

        properties.setMaxBodyCacheBytes(8);
        assertThat(inspect("{\"value\":\"safe\"}" )).isEmpty();

        properties.setEnabled(false);
        List<PayloadDetectionFinding> findings = inspect("{\"comment\":\"<script>\"}" );
        assertThat(findings).isEmpty();
        assertThatThrownBy(() -> findings.add(null)).isInstanceOf(UnsupportedOperationException.class);
    }

    private List<PayloadDetectionFinding> inspect(String json) {
        return inspector.inspect(json.getBytes(StandardCharsets.UTF_8));
    }
}
