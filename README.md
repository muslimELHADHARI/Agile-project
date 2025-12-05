# Vulnerability Scanner API

A comprehensive web-based vulnerability scanning platform built with FastAPI. This application provides advanced security scanning capabilities including port scanning, SQL injection detection, and directory/file enumeration using custom-built detection engines.

## Overview

The Vulnerability Scanner API is a RESTful service that performs security assessments on target systems. It implements three core scanning modules:

1. **Port Scanner**: Identifies open ports and associated services
2. **SQL Injection Scanner**: Detects SQL injection vulnerabilities using multiple detection techniques
3. **Directory Brute-Forcer**: Enumerates directories and files using intelligent pattern matching

All scanning operations are performed asynchronously in the background, allowing for non-blocking API responses and scalable concurrent scanning.

## Features

### Port Scanning
- Comprehensive port range scanning (Quick, Standard, Comprehensive)
- Service identification and version detection
- Concurrent scanning with configurable thread pools
- Vulnerability assessment based on open ports

### SQL Injection Detection
- **Multiple Detection Techniques**:
  - Boolean-based blind SQL injection
  - Time-based blind SQL injection
  - Error-based SQL injection
  - Union-based SQL injection
- **Database Type Detection**: Identifies MySQL, PostgreSQL, MSSQL, Oracle, and SQLite
- **Intelligent Analysis**: Suspicious pattern detection and confidence scoring
- **Comprehensive Reporting**: Detailed vulnerability information with payloads and techniques

### Directory/File Enumeration
- **Advanced Brute-Forcing Engine**:
  - Status code analysis with intelligent filtering
  - Response size comparison to reduce false positives
  - Extension guessing for common file types
  - Redirect following and analysis
- **Smart Baseline Detection**: Multiple sample analysis for accurate filtering
- **Common Path Priority**: Tests high-value targets first
- **Progress Tracking**: Real-time scan progress and statistics

### General Features
- Asynchronous background task processing
- RESTful API design
- Comprehensive error handling and logging
- CORS support for web integration
- In-memory scan result storage
- Multiple scan types (Quick, Standard, Comprehensive)

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Internet connection (for scanning remote targets)

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-username/Agile-project.git
cd Agile-project
```

### Step 2: Create Virtual Environment (Recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Verify Installation

Ensure the wordlist file exists:
```bash
ls ressources/wordlist.txt
```

## Running the Application

### Development Mode

Start the FastAPI server using uvicorn:

```bash
uvicorn scan_server:app --host 0.0.0.0 --port 8000 --reload
```

### Production Mode

For production deployments, use gunicorn with uvicorn workers:

```bash
gunicorn scan_server:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### Docker Deployment

Build and run using Docker:

```bash
docker build -t vulnerability-scanner .
docker run -p 8000:8000 vulnerability-scanner
```

The API will be accessible at `http://localhost:8000`.

## API Documentation

### Base Endpoints

#### Health Check
- **Endpoint**: `GET /health`
- **Description**: Verifies API service availability
- **Response**:
  ```json
  {
    "status": "healthy"
  }
  ```

#### Root Endpoint
- **Endpoint**: `GET /`
- **Description**: Returns welcome message
- **Response**:
  ```json
  {
    "message": "Our Agile-Project server is running"
  }
  ```

### Port Scanning Endpoints

#### Initiate Port Scan
- **Endpoint**: `POST /scan`
- **Description**: Starts a new port scan and vulnerability assessment
- **Request Body**:
  ```json
  {
    "target": "example.com",
    "scanType": "quick"
  }
  ```
- **Scan Types**:
  - `quick`: Scans common ports (approximately 30 ports)
  - `standard`: Scans first 1024 ports
  - `comprehensive`: Scans first 10,000 ports
- **Response**: Returns initial scan object with scan ID and status
  ```json
  {
    "id": "uuid-string",
    "target": "example.com",
    "scanType": "quick",
    "timestamp": "2024-01-01T12:00:00",
    "status": "in_progress"
  }
  ```

#### Get Port Scan Results
- **Endpoint**: `GET /scan/{scan_id}`
- **Description**: Retrieves scan status and results
- **Response**: Complete scan object with open ports and vulnerabilities

### SQL Injection Scanning Endpoints

#### Initiate SQL Injection Scan
- **Endpoint**: `POST /scan/sqlmap`
- **Description**: Starts SQL injection vulnerability detection scan
- **Request Body**:
  ```json
  {
    "target": "http://example.com/page.php?id=1",
    "scanType": "quick"
  }
  ```
- **Response**: Returns scan object with initial status

#### Get SQL Injection Scan Results
- **Endpoint**: `GET /scan/sqlmap/{scan_id}`
- **Description**: Retrieves SQL injection scan results
- **Response**: Scan object containing:
  - Detected vulnerabilities
  - Tested parameters
  - Database type information
  - Confidence levels
  - Payloads used

### Directory Enumeration Endpoints

#### Initiate Directory Brute-Force Scan
- **Endpoint**: `POST /scan/gobuster`
- **Description**: Starts directory and file enumeration scan
- **Request Body**:
  ```json
  {
    "target": "http://example.com",
    "scanType": "quick"
  }
  ```
- **Response**: Returns scan object with initial status

#### Get Directory Scan Results
- **Endpoint**: `GET /scan/gobuster/{scan_id}`
- **Description**: Retrieves directory enumeration results
- **Response**: Scan object containing:
  - Found endpoints
  - Status codes
  - Response sizes
  - Content types
  - Statistics

## Usage Examples

### Port Scanning

```bash
# Start a quick port scan
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scanType": "quick"
  }'

# Retrieve results (replace SCAN_ID with actual ID from previous response)
curl -X GET "http://localhost:8000/scan/SCAN_ID"
```

### SQL Injection Detection

```bash
# Start SQL injection scan
curl -X POST "http://localhost:8000/scan/sqlmap" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://testphp.vulnweb.com/listproducts.php?cat=1",
    "scanType": "standard"
  }'

# Get results after scan completes (wait 5-10 seconds)
curl -X GET "http://localhost:8000/scan/sqlmap/SCAN_ID"
```

### Directory Enumeration

```bash
# Start directory brute-force scan
curl -X POST "http://localhost:8000/scan/gobuster" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://testphp.vulnweb.com",
    "scanType": "comprehensive"
  }'

# Retrieve results
curl -X GET "http://localhost:8000/scan/gobuster/SCAN_ID"
```

### Complete Workflow Example

```bash
# 1. Start scan and capture scan ID
RESPONSE=$(curl -s -X POST "http://localhost:8000/scan/sqlmap" \
  -H "Content-Type: application/json" \
  -d '{"target": "http://example.com/page.php?id=1", "scanType": "quick"}')

# 2. Extract scan ID (requires jq)
SCAN_ID=$(echo $RESPONSE | jq -r '.id')

# 3. Wait for scan to complete
sleep 10

# 4. Retrieve results
curl -X GET "http://localhost:8000/scan/sqlmap/$SCAN_ID" | jq
```

## Technical Details

### SQL Injection Detection Engine

The SQL injection scanner implements four primary detection techniques:

1. **Boolean-Based Blind**: Tests payloads that cause different page responses
2. **Time-Based Blind**: Detects delays in response times (SLEEP, WAITFOR DELAY)
3. **Error-Based**: Identifies SQL error messages in responses
4. **Union-Based**: Tests UNION SELECT payloads for data extraction

The engine automatically:
- Extracts and tests all URL parameters
- Detects database type from error messages
- Calculates confidence scores based on multiple factors
- Provides detailed payload information

### Directory Brute-Forcing Engine

The directory enumeration engine uses:

- **Baseline Analysis**: Tests multiple non-existent endpoints to establish baseline response patterns
- **Size Filtering**: Compares response sizes to filter false positives (10% threshold or 100-byte difference)
- **Status Code Analysis**: Accepts valid status codes (200, 301, 302, 401, 403, etc.)
- **Extension Guessing**: Tests common file extensions automatically
- **Redirect Following**: Follows redirects to discover final destinations
- **Common Path Priority**: Tests high-value targets first (admin, api, config, etc.)

### Port Scanning Engine

The port scanner:
- Uses socket connections for port testing
- Implements concurrent scanning with ThreadPoolExecutor
- Identifies services based on port numbers
- Performs vulnerability assessment based on open services

## Scan Types

### Quick Scan
- **Ports**: Common ports only (~30)
- **SQL Injection**: Top 5 payloads per technique
- **Directory**: 200 words, 7 extensions
- **Duration**: ~30 seconds to 2 minutes

### Standard Scan
- **Ports**: First 1024 ports
- **SQL Injection**: Top 10 payloads per technique
- **Directory**: 1000 words, 15 extensions
- **Duration**: ~2 to 5 minutes

### Comprehensive Scan
- **Ports**: First 10,000 ports
- **SQL Injection**: Full payload set
- **Directory**: Full wordlist, all extensions
- **Duration**: ~5 to 15 minutes (varies by target)

## Response Models

### Scan Object

```json
{
  "id": "string",
  "target": "string",
  "scanType": "quick|standard|comprehensive",
  "timestamp": "ISO 8601 datetime",
  "status": "in_progress|completed|failed",
  "openPorts": [
    {
      "port": 80,
      "state": "open",
      "service": "http"
    }
  ],
  "vulnerabilities": [
    {
      "name": "string",
      "severity": "Critical|High|Medium|Low",
      "description": "string",
      "solution": "string"
    }
  ],
  "rawOutput": "string",
  "sqlmapResult": {}
}
```

## Configuration

### Environment Variables

The application can be configured using environment variables:

- `HOST`: Server host (default: `0.0.0.0`)
- `PORT`: Server port (default: `8000`)
- `LOG_LEVEL`: Logging level (default: `INFO`)

### Wordlist Location

Default wordlist location: `ressources/wordlist.txt`

The wordlist should contain one word per line. If the wordlist is not found, the scanner falls back to a built-in common directory list.

## Project Structure

```
Agile-project/
├── scan_server.py          # Main FastAPI application
├── requirements.txt        # Python dependencies
├── Dockerfile             # Docker configuration
├── README.md              # This file
└── ressources/
    └── wordlist.txt       # Directory enumeration wordlist
```

## Dependencies

Key dependencies include:

- `fastapi`: Web framework for building APIs
- `uvicorn`: ASGI server
- `requests`: HTTP library for scanning
- `pydantic`: Data validation
- `concurrent.futures`: Concurrent execution

See `requirements.txt` for complete dependency list.

## Security Considerations

**Important**: This tool is designed for authorized security testing only. Users must:

1. Obtain explicit written permission before scanning any target
2. Comply with all applicable laws and regulations
3. Use responsibly and ethically
4. Not use for malicious purposes

The scanner disables SSL verification warnings for testing purposes. In production environments, proper SSL certificate validation should be enabled.

## Error Handling

The API provides comprehensive error handling:

- **404 Not Found**: Scan ID does not exist
- **500 Internal Server Error**: Server-side errors during scanning
- **Timeout Errors**: Handled gracefully with appropriate logging

All errors are logged with detailed information for debugging.

## Performance

- **Concurrent Scanning**: Uses ThreadPoolExecutor for parallel operations
- **Background Tasks**: All scans run asynchronously
- **Resource Management**: Configurable worker threads (default: 50)
- **Memory**: In-memory storage for scan results (consider persistence for production)

## Limitations

1. **In-Memory Storage**: Scan results are stored in memory and lost on server restart
2. **No Authentication**: API endpoints are currently unauthenticated
3. **Rate Limiting**: No built-in rate limiting (implement for production)
4. **POST Scanning**: SQL injection scanner currently only tests GET parameters
5. **Wordlist Size**: Large wordlists may require significant time for comprehensive scans

## Future Enhancements

Potential improvements:

- Database persistence for scan results
- User authentication and authorization
- Rate limiting and request throttling
- POST parameter testing for SQL injection
- WebSocket support for real-time progress updates
- Export functionality (JSON, CSV, PDF reports)
- Scheduled scans
- Scan result comparison and trending

## Contributing

Contributions are welcome. Please ensure:

1. Code follows PEP 8 style guidelines
2. All new features include appropriate tests
3. Documentation is updated
4. Security considerations are addressed

## License

[Specify your license here]

## Support

For issues, questions, or contributions, please open an issue on the project repository.

## Acknowledgments

Built with FastAPI, Python, and open-source security tools. The scanning engines are custom implementations designed for educational and authorized security testing purposes.
