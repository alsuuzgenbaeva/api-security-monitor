package com.apisecurity.monitor.requestlog.repository;

public interface ErrorRateWindowStatistics {

    long getTotalRequestCount();

    long getClientErrorCount();

    long getServerErrorCount();
}
