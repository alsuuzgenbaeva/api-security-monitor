package com.apisecurity.monitor.anomaly.payload.service;

import com.apisecurity.monitor.anomaly.payload.config.QueryPayloadDetectionProperties;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding;
import org.springframework.stereotype.Service;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.ObjectMapper;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Service
public class JsonRequestBodyPayloadInspector {

    private static final Set<String> SENSITIVE_FIELD_NAMES = Set.of(
            "password",
            "passwd",
            "passcode",
            "pin",
            "token",
            "accesstoken",
            "refreshtoken",
            "idtoken",
            "apikey",
            "apikeyvalue",
            "secret",
            "clientsecret",
            "privatekey",
            "privatekeypem",
            "authorization",
            "auth",
            "authentication",
            "credential",
            "credentials"
    );

    private final QueryPayloadDetectionProperties properties;
    private final PayloadSignatureDetector signatureDetector;
    private final ObjectMapper objectMapper;

    public JsonRequestBodyPayloadInspector(
            QueryPayloadDetectionProperties properties,
            PayloadSignatureDetector signatureDetector,
            ObjectMapper objectMapper
    ) {
        this.properties = properties;
        this.signatureDetector = signatureDetector;
        this.objectMapper = objectMapper;
    }

    public List<PayloadDetectionFinding> inspect(byte[] body) {
        if (!properties.isEnabled() || body == null || body.length == 0
                || body.length > properties.getMaxBodyCacheBytes()) {
            return List.of();
        }

        String json;
        try {
            json = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(body))
                    .toString();
        } catch (CharacterCodingException invalidUtf8) {
            return List.of();
        }

        return inspectValidatedJson(json);
    }

    private List<PayloadDetectionFinding> inspectValidatedJson(String json) {
        Set<PayloadDetectionFinding> findings = new LinkedHashSet<>();
        Deque<Boolean> sensitiveContainers = new ArrayDeque<>();
        boolean nextValueSensitive = false;
        int depth = 0;
        int rootValues = 0;
        int inspectedValues = 0;

        try (JsonParser parser = objectMapper.createParser(json)) {
            JsonToken token;
            while ((token = parser.nextToken()) != null) {
                boolean containerSensitive = !sensitiveContainers.isEmpty() && sensitiveContainers.peek();

                if (token == JsonToken.PROPERTY_NAME) {
                    nextValueSensitive = containerSensitive || isSensitiveField(parser.currentName());
                    continue;
                }

                if (token == JsonToken.START_OBJECT || token == JsonToken.START_ARRAY) {
                    if (depth == 0) {
                        rootValues++;
                    }
                    boolean valueSensitive = containerSensitive || nextValueSensitive;
                    sensitiveContainers.push(valueSensitive);
                    depth++;
                    nextValueSensitive = false;
                    continue;
                }

                if (token == JsonToken.END_OBJECT || token == JsonToken.END_ARRAY) {
                    if (sensitiveContainers.isEmpty()) {
                        return List.of();
                    }
                    sensitiveContainers.pop();
                    depth--;
                    nextValueSensitive = false;
                    continue;
                }

                if (depth == 0) {
                    rootValues++;
                }
                boolean valueSensitive = containerSensitive || nextValueSensitive;
                nextValueSensitive = false;

                if (token == JsonToken.VALUE_STRING
                        && !valueSensitive
                        && depth <= properties.getMaxJsonDepth()) {
                    if (inspectedValues >= properties.getMaxJsonValues()) {
                        continue;
                    }
                    inspectedValues++;
                    if (parser.getStringLength() > properties.getMaxJsonStringLength()) {
                        continue;
                    }
                    findings.addAll(signatureDetector.detectBodyValue(parser.getString()));
                }
            }
        } catch (JacksonException invalidJsonOrParserSafetyFailure) {
            return List.of();
        }

        if (rootValues != 1 || depth != 0) {
            return List.of();
        }
        return List.copyOf(findings);
    }

    private boolean isSensitiveField(String fieldName) {
        if (fieldName == null) {
            return false;
        }
        StringBuilder normalized = new StringBuilder(fieldName.length());
        for (int index = 0; index < fieldName.length(); index++) {
            char character = Character.toLowerCase(fieldName.charAt(index));
            if ((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')) {
                normalized.append(character);
            }
        }
        String normalizedName = normalized.toString();
        return SENSITIVE_FIELD_NAMES.contains(normalizedName)
                || normalizedName.contains("password")
                || normalizedName.contains("token")
                || normalizedName.contains("secret")
                || normalizedName.contains("credential")
                || normalizedName.contains("authorization")
                || normalizedName.endsWith("apikey")
                || normalizedName.endsWith("privatekey");
    }
}
