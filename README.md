# AVGuard: Multi-Container Malware Scanning Application

### Overview

**AVGuard** is a containerized web application designed for malware scanning by utilizing the VirusTotal API. The application consists of two Docker containers:
- **Frontend Container**: Built using Django, it allows users to upload files for malware scanning.
- **Backend Storage Container**: Securely stores the uploaded files (potential malware) in an isolated environment, preventing them from affecting the frontend or the rest of the system. The uploaded files are scanned by the VirusTotal API, and the results are displayed in the frontend.

---

## Features
- **File Upload**: A simple web-based interface for uploading files.
- **Secure File Storage**: Malware files are stored separately in a dedicated Docker container for isolation.
- **VirusTotal API Integration**: The files are scanned using the VirusTotal API for malware analysis.
- **Dockerized Environment**: The entire application is containerized with separate Docker containers for the frontend and file storage.

---

## Installation Instructions

Follow these steps to set up and run AVGuard on your local machine using Docker.

### 1. Clone the Repository
Start by cloning the AVGuard repository from GitHub:

```bash
git clone https://github.com/yourusername/AVGuard.git
cd AVGuard
```

### 2. To allow the frontend and backend containers to communicate, create a Docker network.

```bash
docker network create avguard-network
```

### 3. Build and Run the Frontend (Django Application)

Navigate to the AVGuard directory and build the Docker image for the Django-based frontend. This container handles the file upload and displays the scan results.

```bash
cd AVGuard
sudo docker build -t <YOUR-FRONTEND-IMAGE-NAME> .
```
Once built, run the container by linking it to the previously created Docker network.

```bash
sudo docker run -d --name <YOUR-FRONTEND-IMAGE-NAME> --network avguard-network -p 8000:8000 <YOUR-FRONTEND-IMAGE-NAME>
```
