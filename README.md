API Security Monitor

A REST API monitoring application built with Java and Spring Boot.

The application logs HTTP requests, detects unusual request activity and displays the results in a web dashboard.

Technologies

* Java 21
* Spring Boot 4.1.2
* Spring Security
* PostgreSQL 16
* Maven
* HTML, CSS, JavaScript

Features

* HTTP request logging
* Request history stored in PostgreSQL
* Rule-based anomaly detection
* Security events with risk levels
* Admin authentication
* Web dashboard with request statistics and security events

Currently, the detection mechanism checks for excessive requests from the same IP address (5 requests within 10 seconds). Detected activity is recorded as a security event without blocking the request.

Setup

Requires Java 21, PostgreSQL 16 and a database named api_security_db.

Set the following environment variables:

$env:DB_PASSWORD = "your_database_password"
$env:MONITOR_ADMIN_PASSWORD = "your_admin_password"

Run the application:

.\mvnw.cmd spring-boot:run

Dashboard: http://127.0.0.1:8080/monitoring

Default username: admin

API Endpoints

Method	Endpoint	Description
GET	/api/test	Test endpoint
GET	/api/monitoring/summary	Monitoring statistics
GET	/api/monitoring/requests	Request logs
GET	/api/monitoring/events	Security events

Monitoring endpoints require authentication.

Tests

.\mvnw.cmd clean test

Development

Request logging, rule-based detection and the monitoring dashboard are implemented.

Machine learning-based anomaly detection and additional security checks are planned for future development.
