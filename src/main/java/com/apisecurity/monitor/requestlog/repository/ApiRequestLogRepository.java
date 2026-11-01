package com.apisecurity.monitor.requestlog.repository;

import com.apisecurity.monitor.requestlog.model.ApiRequestLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApiRequestLogRepository extends JpaRepository<ApiRequestLog, Long> {
}
