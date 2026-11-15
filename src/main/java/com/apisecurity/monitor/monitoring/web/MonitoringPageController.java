package com.apisecurity.monitor.monitoring.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MonitoringPageController {

    @GetMapping({"/monitoring", "/monitoring/"})
    public String dashboard() {
        return "forward:/monitoring/index.html";
    }
}
