package com.apisecurity.monitor.anomaly.payload.service;

import com.apisecurity.monitor.anomaly.payload.config.QueryPayloadDetectionProperties;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.InputLocation;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.SignatureIdentifier;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriUtils;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class PayloadSignatureDetector {

    private static final List<SignaturePattern> SIGNATURE_PATTERNS = List.of(
            signature(SignatureIdentifier.XSS_SCRIPT_TAG, "<\\s*/?\\s*script\\b"),
            signature(SignatureIdentifier.XSS_EVENT_HANDLER,
                    "<[^>\\r\\n]{0,256}\\bon(?:error|load|click|mouseover|focus)\\s*="),
            signature(SignatureIdentifier.XSS_JAVASCRIPT_URI,
                    "\\bjavascript\\s*:\\s*(?:(?:alert|confirm|prompt|eval|fetch)\\s*\\("
                            + "|(?:document|window|location)\\s*(?:\\.|\\[|=))"),
            signature(SignatureIdentifier.SQLI_UNION_SELECT,
                    "(?:(?:['\"`)\\d]|\\bnull\\b)\\s+union\\s+(?:all\\s+)?select\\b"
                            + "|\\bunion\\s+(?:all\\s+)?select\\b[^\\r\\n]{0,128}\\bfrom\\b)"),
            signature(SignatureIdentifier.SQLI_BOOLEAN_TAUTOLOGY,
                    "(?:['\"]\\s*|\\b\\d{1,10}\\s+)(?:or|and)\\s+"
                            + "['\"]?1['\"]?\\s*=\\s*['\"]?1['\"]?\\b")
    );

    private final QueryPayloadDetectionProperties properties;

    public PayloadSignatureDetector(QueryPayloadDetectionProperties properties) {
        this.properties = properties;
    }

    public List<PayloadDetectionFinding> detect(String rawQuery) {
        if (!properties.isEnabled() || rawQuery == null || rawQuery.isEmpty()) {
            return List.of();
        }

        String boundedQuery = truncate(rawQuery, properties.getMaxQueryLength());
        Set<PayloadDetectionFinding> findings = new LinkedHashSet<>();
        int parameterStart = 0;
        int inspectedParameters = 0;

        while (parameterStart <= boundedQuery.length()
                && inspectedParameters < properties.getMaxParameters()) {
            int parameterEnd = boundedQuery.indexOf('&', parameterStart);
            if (parameterEnd < 0) {
                parameterEnd = boundedQuery.length();
            }

            inspectParameter(boundedQuery.substring(parameterStart, parameterEnd), findings);
            inspectedParameters++;

            if (parameterEnd == boundedQuery.length()) {
                break;
            }
            parameterStart = parameterEnd + 1;
        }

        return List.copyOf(findings);
    }

    public List<PayloadDetectionFinding> detectPath(String rawPath) {
        if (!properties.isEnabled() || rawPath == null || rawPath.isEmpty()) {
            return List.of();
        }

        String boundedPath = truncate(rawPath, properties.getMaxPathLength());
        Set<PayloadDetectionFinding> findings = new LinkedHashSet<>();
        inspectCanonicalValue(boundedPath, InputLocation.REQUEST_PATH, findings);

        String decodedPath = decodePathOnce(boundedPath);
        if (!decodedPath.equals(boundedPath)) {
            inspectCanonicalValue(decodedPath, InputLocation.REQUEST_PATH, findings);
        }
        return List.copyOf(findings);
    }

    public List<PayloadDetectionFinding> detectBodyValue(String value) {
        if (!properties.isEnabled() || value == null || value.isEmpty()) {
            return List.of();
        }

        Set<PayloadDetectionFinding> findings = new LinkedHashSet<>();
        inspectCanonicalValue(
                truncate(value, properties.getMaxJsonStringLength()),
                InputLocation.REQUEST_BODY,
                findings);
        return List.copyOf(findings);
    }

    private void inspectParameter(String rawParameter, Set<PayloadDetectionFinding> findings) {
        int separator = rawParameter.indexOf('=');
        String rawName = separator < 0 ? rawParameter : rawParameter.substring(0, separator);
        String rawValue = separator < 0 ? "" : rawParameter.substring(separator + 1);
        inspectValue(rawName, findings);
        inspectValue(rawValue, findings);
    }

    private void inspectValue(String rawValue, Set<PayloadDetectionFinding> findings) {
        String boundedValue = truncate(rawValue, properties.getMaxParameterLength());
        inspectCanonicalValue(boundedValue, InputLocation.QUERY_PARAMETER, findings);

        String decodedValue = decodeOnce(boundedValue);
        if (!decodedValue.equals(boundedValue)) {
            inspectCanonicalValue(decodedValue, InputLocation.QUERY_PARAMETER, findings);
        }
    }

    private void inspectCanonicalValue(
            String value,
            InputLocation inputLocation,
            Set<PayloadDetectionFinding> findings
    ) {
        for (SignaturePattern signaturePattern : SIGNATURE_PATTERNS) {
            if (signaturePattern.pattern().matcher(value).find()) {
                SignatureIdentifier identifier = signaturePattern.identifier();
                findings.add(new PayloadDetectionFinding(
                        identifier.eventType(), inputLocation, identifier));
            }
        }
    }

    private String decodeOnce(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException malformedEncoding) {
            return decodeValidAsciiSequences(value);
        }
    }

    private String decodePathOnce(String value) {
        try {
            return UriUtils.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException malformedEncoding) {
            return decodeValidAsciiSequences(value, false);
        }
    }

    private String decodeValidAsciiSequences(String value) {
        return decodeValidAsciiSequences(value, true);
    }

    private String decodeValidAsciiSequences(String value, boolean plusAsSpace) {
        StringBuilder decoded = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (current == '+' && plusAsSpace) {
                decoded.append(' ');
                continue;
            }
            if (current == '%' && index + 2 < value.length()) {
                int high = Character.digit(value.charAt(index + 1), 16);
                int low = Character.digit(value.charAt(index + 2), 16);
                int decodedByte = high < 0 || low < 0 ? -1 : (high << 4) + low;
                if (decodedByte >= 0 && decodedByte <= 0x7f) {
                    decoded.append((char) decodedByte);
                    index += 2;
                    continue;
                }
            }
            decoded.append(current);
        }
        return decoded.toString();
    }

    private String truncate(String value, int maximumLength) {
        return value.length() <= maximumLength ? value : value.substring(0, maximumLength);
    }

    private static SignaturePattern signature(SignatureIdentifier identifier, String expression) {
        return new SignaturePattern(identifier, Pattern.compile(
                expression, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE));
    }

    private record SignaturePattern(SignatureIdentifier identifier, Pattern pattern) {
    }
}
