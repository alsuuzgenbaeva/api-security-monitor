package com.apisecurity.monitor.monitoring.web;

import com.apisecurity.monitor.monitoring.dto.MonitoringSummaryResponse;
import com.apisecurity.monitor.monitoring.dto.PagedResponse;
import com.apisecurity.monitor.monitoring.dto.RequestLogResponse;
import com.apisecurity.monitor.monitoring.dto.SecurityEventResponse;
import com.apisecurity.monitor.monitoring.service.MonitoringQueryService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/monitoring")
public class MonitoringController {

    private final MonitoringQueryService monitoringQueryService;

    public MonitoringController(MonitoringQueryService monitoringQueryService) {
        this.monitoringQueryService = monitoringQueryService;
    }

    @GetMapping("/summary")
    public MonitoringSummaryResponse summary() {
        return monitoringQueryService.getSummary();
    }

    @GetMapping("/requests")
    public PagedResponse<RequestLogResponse> requests(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        return monitoringQueryService.getRequests(page, size);
    }

    @GetMapping("/events")
    public PagedResponse<SecurityEventResponse> events(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        return monitoringQueryService.getEvents(page, size);
    }
}
