package com.apisecurity.monitor.anomaly.payload.service;

import com.apisecurity.monitor.anomaly.payload.config.QueryPayloadDetectionProperties;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.SignatureIdentifier;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PayloadSignatureDetectorTest {

    private QueryPayloadDetectionProperties properties;
    private PayloadSignatureDetector detector;

    @BeforeEach
    void setUp() {
        properties = new QueryPayloadDetectionProperties();
        detector = new PayloadSignatureDetector(properties);
    }

    @Test
    void ignoresNormalAndPotentiallyAmbiguousQueryValues() {
        List<PayloadDetectionFinding> findings = detector.detect(
                "name=O%27Connor&topic=select+plan&document=script+documentation"
                        + "&range=1--1&expression=1+or+color%3Dblue"
                        + "&language=JavaScript%3A+advanced+patterns"
                        + "&lesson=SQL+UNION+SELECT+tutorial");

        assertThat(findings).isEmpty();
    }

    @Test
    void detectsHighConfidenceXssSignaturesAndDeduplicatesThem() {
        List<PayloadDetectionFinding> findings = detector.detect(
                "q=<script>alert(1)</script>&duplicate=<SCRIPT>x</SCRIPT>"
                        + "&image=<img src=x onerror=alert(1)>&link=javascript:alert(1)");

        assertThat(findings)
                .extracting(PayloadDetectionFinding::signatureIdentifier)
                .containsExactly(
                        SignatureIdentifier.XSS_SCRIPT_TAG,
                        SignatureIdentifier.XSS_EVENT_HANDLER,
                        SignatureIdentifier.XSS_JAVASCRIPT_URI);
        assertThat(findings).extracting(PayloadDetectionFinding::eventType)
                .containsOnly(SecurityEventType.XSS_ATTEMPT);
    }

    @Test
    void detectsHighConfidenceSqlInjectionSignatures() {
        List<PayloadDetectionFinding> findings = detector.detect(
                "filter=' OR '1'='1&columns=1 UNION ALL SELECT password");

        assertThat(findings)
                .extracting(PayloadDetectionFinding::signatureIdentifier)
                .containsExactly(
                        SignatureIdentifier.SQLI_BOOLEAN_TAUTOLOGY,
                        SignatureIdentifier.SQLI_UNION_SELECT);
        assertThat(findings).extracting(PayloadDetectionFinding::eventType)
                .containsOnly(SecurityEventType.SQL_INJECTION_ATTEMPT);
    }

    @Test
    void decodesPercentEncodedAndPlusSeparatedInputOnce() {
        List<PayloadDetectionFinding> findings = detector.detect(
                "x=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
                        + "&sql=1+UNION+SELECT+password");

        assertThat(findings)
                .extracting(PayloadDetectionFinding::signatureIdentifier)
                .containsExactly(
                        SignatureIdentifier.XSS_SCRIPT_TAG,
                        SignatureIdentifier.SQLI_UNION_SELECT);
    }

    @Test
    void detectsContextualJavaScriptUriAndUnionSelectIndicators() {
        List<PayloadDetectionFinding> findings = detector.detect(
                "link=javascript%3Adocument.cookie"
                        + "&query=UNION+SELECT+password+FROM+users");

        assertThat(findings)
                .extracting(PayloadDetectionFinding::signatureIdentifier)
                .containsExactly(
                        SignatureIdentifier.XSS_JAVASCRIPT_URI,
                        SignatureIdentifier.SQLI_UNION_SELECT);
    }

    @Test
    void malformedEncodingDoesNotFailAndValidSequencesAreStillInspected() {
        List<PayloadDetectionFinding> findings = detector.detect("q=%ZZ%3Cscript%3E");

        assertThat(findings)
                .extracting(PayloadDetectionFinding::signatureIdentifier)
                .containsExactly(SignatureIdentifier.XSS_SCRIPT_TAG);
    }

    @Test
    void enforcesMaximumQueryLength() {
        properties.setMaxQueryLength(12);

        assertThat(detector.detect("safe=123456&q=<script>")).isEmpty();
    }

    @Test
    void enforcesMaximumParameterLength() {
        properties.setMaxParameterLength(8);

        assertThat(detector.detect("q=aaaaaaaa<script>")).isEmpty();
    }

    @Test
    void enforcesMaximumParameterCount() {
        properties.setMaxParameters(1);

        assertThat(detector.detect("safe=value&q=<script>")).isEmpty();
    }

    @Test
    void disabledDetectionReturnsAnImmutableEmptyResult() {
        properties.setEnabled(false);

        List<PayloadDetectionFinding> findings = detector.detect("q=<script>");

        assertThat(findings).isEmpty();
        assertThatThrownBy(() -> findings.add(null))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void returnedFindingsAreImmutable() {
        List<PayloadDetectionFinding> findings = detector.detect("q=<script>");

        assertThatThrownBy(() -> findings.clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
