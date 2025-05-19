# NetworkScanner

AI/ML-Enhanced Network Scanner

### Updates:

Currently using the National Vulnerability database to get the vulnerability data (CVE) that is associated with the scan results

E.g. Scan result with "Apache httpd" as the product and "2.4.7" as the version, the cve lookup should search the database through the API to get all the vulnerabilities related to "Apache httpd 2.4.7"

## Overview

This project enhances traditional network scanners with AI/ML capabilities to prioritize vulnerabilities, and provide automated reporting. By combining machine learning, natural language processing (NLP), and optimized scanning workflows, this tool automates and improves vulnerability management, making it easier to identify and address critical security issues.

A chance for me to learn many different things and see if I can combine them and create something worth-while

## Key Features

- **Prioritize Vulnerabilities**: Predict which vulnerabilities are most likely to be exploited using ML models.
- **Automated Reporting**: Generate human-readable summaries of scan results using NLP.

## Technical Workflow

### 1. Data Collection

- **Sources**:
  - Network Scans: Gather data using tools like `nmap`
  - Vulnerability Databases: Fetch CVE details from the NVD API or CVE Details.
  - Network Traffic Logs: Capture flow data

### 2. Data Preprocessing

- **Feature Engineering**:
  - For prioritization: CVSS score, CVE age, affected software popularity, patch availability.
  - For anomaly detection: Packet size, protocol distribution, traffic volume.
- **Labeling**:
  - Use historical exploit data (e.g., Exploit-DB) to train supervised models.

### 3. Integration with Scanner

Use Python to integrate the ML models with scanning tools.

### 4. Reporting & Visualization

- **NLP Summaries**:
  - Example: "Critical Risk: Port 22 (SSH) is open with an outdated OpenSSL version (CVE-2021-3449). Patch immediately."
