package com.apisecurity.monitor.testapi;

import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Profile({"local", "demo"})
@RestController
@RequestMapping("/api/demo/payload")
public class JsonPayloadDemoController {

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> inspect(@RequestBody Object ignoredBody) {
        return Map.of("message", "JSON payload received for monitoring");
    }
}
