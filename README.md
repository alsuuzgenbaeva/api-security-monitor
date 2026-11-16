API Security Monitor

This is my graduation project for the Computer Engineering Department at Erciyes University.

The aim of the project is to develop a system that monitors REST API traffic and detects unusual request activity. The system currently uses rule-based detection, with machine learning planned for the next stage of development.

Technologies

* Java 21
* Spring Boot 4.1.2
* Spring Security
* PostgreSQL 16
* Maven
* HTML, CSS, JavaScript

Features

The current version includes:

* Automatic logging of HTTP requests
* Storage of request information in PostgreSQL
* Detection of excessive requests from the same IP address
* Security event generation
* Administrator login
* A web dashboard for viewing request logs and security events

For each request, the system records information such as the IP address, HTTP method, endpoint, response status and request duration.

The anomaly detection module currently checks whether an IP address sends 5 requests within 10 seconds. When this happens, a security event with a MEDIUM risk level is created.

The system only records suspicious activity. It does not block requests.

How to Run

Requirements

* Java 21
* PostgreSQL 16
* A database named api_security_db

1. Configure the database

Create a PostgreSQL database named api_security_db.

The application uses the postgres database user.

2. Set environment variables

Before running the application, set the database and dashboard passwords.

In PowerShell:

$env:DB_PASSWORD = "your_database_password"
$env:MONITOR_ADMIN_PASSWORD = "your_admin_password"

The default dashboard username is admin.

3. Start the application

.\mvnw.cmd spring-boot:run

The application runs locally at:

http://127.0.0.1:8080

4. Open the dashboard

Go to:

http://127.0.0.1:8080/monitoring

Log in using the administrator credentials.

The dashboard displays request statistics, recent API requests and detected security events.

API Endpoints

Method	Endpoint	Description
GET	/api/test	Test endpoint
GET	/api/monitoring/summary	Request and event statistics
GET	/api/monitoring/requests	Recorded API requests
GET	/api/monitoring/events	Detected security events

The monitoring endpoints require administrator login.

Testing

To run the automated tests:

.\mvnw.cmd clean test

You can also test the anomaly detection manually.

First, start the application and open the dashboard. Then run this command in PowerShell:

1..5 | ForEach-Object {
    Invoke-RestMethod http://127.0.0.1:8080/api/test
}

Refresh the dashboard to see the recorded requests and the generated security event.

If the test was recently repeated, wait at least 30 seconds before trying again.

Current Progress

The first working prototype is complete. It includes HTTP request logging, basic rule-based anomaly detection and a monitoring dashboard.

The next part of the project will focus on:

* Machine learning-based anomaly detection
* Additional security rules
* Integration of the detection methods
* Further testing and improvements

The project is still under development and is currently intended for local testing.
