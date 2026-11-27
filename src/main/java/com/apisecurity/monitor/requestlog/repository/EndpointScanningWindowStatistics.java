package com.apisecurity.monitor.requestlog.repository;

public interface EndpointScanningWindowStatistics {

    long getUnsuccessfulRequestCount();

    long getDistinctPathCount();
}
