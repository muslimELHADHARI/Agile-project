"""
Vulnerability Scanner API

This FastAPI application provides a web-based vulnerability scanner. It allows users to initiate
port scans and basic vulnerability checks against specified targets. The scans are performed
as background tasks, and their status and results can be retrieved via dedicated endpoints.
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
import asyncio
import uuid
from datetime import datetime
import logging
from enum import Enum
import socket
import json
import concurrent.futures
import requests
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import random
import string

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Vulnerability Scanner API",docs_url=None, redoc_url=None, openapi_url=None)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enums
class ScanType(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"

class ScanStatus(str, Enum):
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

# Models
class PortInfo(BaseModel):
    port: int
    state: str
    service: Optional[str] = None
    version: Optional[str] = None

class Vulnerability(BaseModel):
    name: str
    severity: str
    description: str
    solution: Optional[str] = None

class ScanRequest(BaseModel):
    target: str
    scanType: ScanType

class Scan(BaseModel):
    id: str
    target: str
    scanType: ScanType
    timestamp: str
    status: ScanStatus
    openPorts: Optional[List[PortInfo]] = None
    vulnerabilities: Optional[List[Vulnerability]] = None
    rawOutput: Optional[str] = None
    sqlmapResult: Optional[dict] = None

    def json(self, **kwargs):
        return json.dumps(self.dict(), **kwargs)

# In-memory storage for scan results
scan_results: Dict[str, Scan] = {}

# Common ports to scan
COMMON_PORTS = [
    1,      # tcpmux
    7,      # echo
    20,     # ftp-data
    21,     # ftp
    22,     # ssh
    23,     # telnet
    25,     # smtp
    53,     # dns
    67,     # dhcp-server
    68,     # dhcp-client
    69,     # tftp
    80,     # http
    110,    # pop3
    111,    # rpcbind
    123,    # ntp
    135,    # msrpc
    137,    # netbios-ns
    138,    # netbios-dgm
    139,    # netbios-ssn
    143,    # imap
    161,    # snmp
    389,    # ldap
    443,    # https
    445,    # microsoft-ds
    465,    # smtps
    514,    # syslog
    587,    # smtp (submission)
    631,    # ipp
    993,    # imaps
    995,    # pop3s
    1080,   # socks
    1433,   # mssql
    1521,   # oracle
    1723,   # pptp
    2049,   # nfs
    2375,   # docker
    3306,   # mysql
    3389,   # rdp
    5432,   # postgresql
    5900,   # vnc
    5985,   # winrm
    6379,   # redis
    8080,   # http-proxy
    8443,   # https-alt
    8888,   # http-alt
    9200,   # elasticsearch
    27017   # mongodb
]
STANDARD_PORTS = list(range(1, 1025))  # First 1024 ports
COMPREHENSIVE_PORTS = list(range(1, 10001))  # First 10000 ports

# Common services
SERVICE_MAP = {
    1: "tcpmux",
    7: "echo",
    9: "discard",
    13: "daytime",
    17: "qotd",
    19: "chargen",
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    70: "gopher",
    79: "finger",
    80: "http",
    81: "hostname",
    82: "xfer",
    83: "mit-ml-dev",
    88: "kerberos",
    89: "kerberos-sec",
    109: "pop2",
    110: "pop3",
    111: "rpcbind",
    113: "ident",
    118: "sqlservices",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    179: "bgp",
    199: "smux",
    264: "bgmp",
    318: "pkix-timestamp",
    389: "ldap",
    427: "slp",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    497: "dantz",
    500: "isakmp",
    514: "syslog",
    515: "printer",
    520: "rip",
    524: "ncp",
    530: "courier",
    540: "uucp",
    554: "rtsp",
    587: "submission",
    593: "http-rpc-epmap",
    623: "ipmi",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    902: "vmware-auth",
    993: "imaps",
    995: "pop3s",
    992: "telnets",
    1001: "webpush",
    1025: "nfs-or-iis",
    1080: "socks",
    1311: "dell-openmanage",
    1433: "ms-sql-s",
    1434: "ms-sql-m",
    1521: "oracle",
    1720: "h323",
    1723: "pptp",
    1812: "radius-auth",
    1813: "radius-acct",
    1830: "oracle-vp2",
    1900: "ssdp",
    1984: "bigbrother",
    2000: "cisco-sccp",
    2049: "nfs",
    2082: "cpanel",
    2083: "cpanel-ssl",
    2100: "amiganetfs",
    2222: "directadmin",
    2375: "docker-api",
    2376: "docker-ssl",
    2379: "etcd-client",
    2380: "etcd-peer",
    24800: "synergy",
    25565: "minecraft",
    27017: "mongodb",
    27018: "mongodb-shard",
    27019: "mongodb-config",
    32764: "router-backdoor",
    3306: "mysql",
    33060: "mysqlx",
    33389: "rdp-alt",
    3389: "rdp",
    3689: "daap",
    3690: "svn",
    4000: "icq",
    4369: "epmd",
    4443: "pharos",
    4444: "metasploit",
    5000: "flask-dev",
    5001: "commplex-link",
    50030: "hadoop-namenode",
    50070: "hadoop-datanode",
    5432: "postgresql",
    5555: "android-debug",
    5601: "kibana",
    5671: "amqps",
    5672: "amqp",
    5800: "vnc-http",
    5900: "vnc",
    5901: "vnc-1",
    5984: "couchdb",
    5985: "winrm",
    5986: "winrm-ssl",
    6000: "X11",
    6001: "X11:1",
    6379: "redis",
    6660: "irc",
    6666: "irc-alt",
    6667: "irc",
    7000: "afs3-fileserver",
    7001: "weblogic",
    7002: "weblogic-ssl",
    7443: "oracle-webpanel",
    7654: "vnc-or-backdoor",
    8000: "http-alt",
    8008: "http-alt2",
    8080: "http-proxy",
    8081: "http-monitor",
    8181: "jboss",
    8200: "miniupnp",
    8443: "https-alt",
    8500: "consul",
    8880: "cpanel-http-alt",
    8883: "mqtt-ssl",
    8888: "http-alt4",
    9000: "php-fpm",
    9001: "tor-or",
    9042: "cassandra",
    9090: "web-console",
    9200: "elasticsearch",
    9300: "elasticsearch-node",
    9997: "splunk-forwarder",
    9999: "abyss",
    10000: "webmin",
    10050: "zabbix-agent",
    10051: "zabbix-trapper",
    11211: "memcached",
    27018: "mongo-shard",
    27019: "mongo-config",
    28017: "mongodb-web",
    28080: "http-alt5"
}
class SQLInjectionDetector:
    """
    Advanced SQL Injection Detection Engine
    Implements multiple detection techniques: Boolean-based, Time-based, Error-based, and Union-based
    """
    
    # SQL injection payloads for different techniques
    BOOLEAN_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR ('1'='1--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL, NULL--",
    ]
    
    TIME_BASED_PAYLOADS = [
        "'; WAITFOR DELAY '00:00:05'--",
        "'; SELECT SLEEP(5)--",
        "'; pg_sleep(5)--",
        "'; (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' OR SLEEP(5)--",
        "' OR pg_sleep(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
    ]
    
    ERROR_BASED_PAYLOADS = [
        "' AND 1=CONVERT(int, @@version)--",
        "' AND 1=CAST(@@version AS int)--",
        "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100--",
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    ]
    
    UNION_BASED_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT 1--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT 1,2,3--",
    ]
    
    DATABASE_SIGNATURES = {
        'MySQL': [
            r'mysql',
            r'you have an error in your sql syntax',
            r'warning: mysql',
            r'valid mysql result',
            r'mysqli_',
            r'mysql_fetch',
        ],
        'PostgreSQL': [
            r'postgresql',
            r'pg_query\(\)',
            r'warning.*\Wpg_',
            r'valid postgresql result',
            r'postgres query failed',
            r'pg_exec\(\)',
        ],
        'MSSQL': [
            r'microsoft.*odbc.*sql server',
            r'sql server.*driver',
            r'warning.*\Wmssql_',
            r'valid mssql result',
            r'mssql_query\(\)',
            r'sqlcmd',
        ],
        'Oracle': [
            r'\boracle\b',
            r'ora-\d{5}',
            r'oracle.*driver',
            r'warning.*\Woci_',
            r'valid oracle result',
            r'oracle query failed',
        ],
        'SQLite': [
            r'sqlite',
            r'sqlite3',
            r'warning.*\Wsqlite_',
            r'valid sqlite result',
            r'sqlite_query\(\)',
        ],
    }
    
    @staticmethod
    def generate_random_string(length=8):
        """Generate random string for testing"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    @staticmethod
    def extract_parameters(url):
        """Extract GET parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return params, parsed
    
    @staticmethod
    def build_url(base_url, params):
        """Build URL with modified parameters"""
        parsed = urlparse(base_url)
        new_query = urlencode(params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)
    
    @staticmethod
    def detect_database_type(response_text, response_headers):
        """Detect database type from error messages"""
        text_lower = response_text.lower()
        headers_str = str(response_headers).lower()
        combined = text_lower + headers_str
        
        detected = []
        for db_type, signatures in SQLInjectionDetector.DATABASE_SIGNATURES.items():
            for signature in signatures:
                if re.search(signature, combined, re.IGNORECASE):
                    detected.append(db_type)
                    break
        
        return list(set(detected)) if detected else ['Unknown']
    
    @staticmethod
    def test_boolean_based(url, param_name, original_value):
        """Test boolean-based SQL injection"""
        test_payloads = SQLInjectionDetector.BOOLEAN_PAYLOADS[:5]  # Test top 5
        
        try:
            # Get baseline response
            baseline_response = requests.get(url, timeout=10, allow_redirects=False)
            baseline_length = len(baseline_response.text)
            baseline_status = baseline_response.status_code
            
            for payload in test_payloads:
                params, parsed = SQLInjectionDetector.extract_parameters(url)
                if param_name in params:
                    params[param_name] = [payload]
                    test_url = SQLInjectionDetector.build_url(url, params)
                    
                    test_response = requests.get(test_url, timeout=10, allow_redirects=False)
                    test_length = len(test_response.text)
                    test_status = test_response.status_code
                    
                    # Check for significant differences
                    length_diff = abs(test_length - baseline_length)
                    if length_diff > baseline_length * 0.1 or test_status != baseline_status:
                        return {
                            'vulnerable': True,
                            'technique': 'Boolean-based',
                            'payload': payload,
                            'baseline_length': baseline_length,
                            'test_length': test_length,
                            'status_code': test_status
                        }
        except Exception as e:
            logger.debug(f"Boolean-based test error: {str(e)}")
        
        return {'vulnerable': False, 'technique': 'Boolean-based'}
    
    @staticmethod
    def test_time_based(url, param_name, original_value):
        """Test time-based SQL injection"""
        time_payloads = SQLInjectionDetector.TIME_BASED_PAYLOADS[:3]  # Test top 3
        
        try:
            for payload in time_payloads:
                params, parsed = SQLInjectionDetector.extract_parameters(url)
                if param_name in params:
                    params[param_name] = [payload]
                    test_url = SQLInjectionDetector.build_url(url, params)
                    
                    start_time = time.time()
                    test_response = requests.get(test_url, timeout=15, allow_redirects=False)
                    elapsed_time = time.time() - start_time
                    
                    # If response took more than 4 seconds, likely vulnerable
                    if elapsed_time >= 4.0:
                        return {
                            'vulnerable': True,
                            'technique': 'Time-based',
                            'payload': payload,
                            'response_time': elapsed_time
                        }
        except requests.exceptions.Timeout:
            # Timeout could indicate time-based injection
            return {
                'vulnerable': True,
                'technique': 'Time-based',
                'payload': payload,
                'response_time': 'timeout'
            }
        except Exception as e:
            logger.debug(f"Time-based test error: {str(e)}")
        
        return {'vulnerable': False, 'technique': 'Time-based'}
    
    @staticmethod
    def test_error_based(url, param_name, original_value):
        """Test error-based SQL injection"""
        error_payloads = SQLInjectionDetector.ERROR_BASED_PAYLOADS[:3]
        
        try:
            for payload in error_payloads:
                params, parsed = SQLInjectionDetector.extract_parameters(url)
                if param_name in params:
                    params[param_name] = [payload]
                    test_url = SQLInjectionDetector.build_url(url, params)
                    
                    test_response = requests.get(test_url, timeout=10, allow_redirects=False)
                    response_text = test_response.text.lower()
                    response_headers = test_response.headers
                    
                    # Check for SQL error messages
                    sql_errors = [
                        r'sql syntax.*mysql',
                        r'warning.*\Wmysql_.*',
                        r'valid mysql result',
                        r'mysqli_query\(\)',
                        r'mysql_fetch',
                        r'postgresql.*error',
                        r'warning.*\Wpg_.*',
                        r'valid postgresql result',
                        r'pg_query\(\)',
                        r'microsoft.*odbc.*sql server',
                        r'sql server.*driver',
                        r'warning.*\Wmssql_.*',
                        r'valid mssql result',
                        r'oracle.*error',
                        r'ora-\d{5}',
                        r'oracle.*driver',
                        r'warning.*\Woci_.*',
                        r'sqlite.*error',
                        r'warning.*\Wsqlite_.*',
                    ]
                    
                    for error_pattern in sql_errors:
                        if re.search(error_pattern, response_text, re.IGNORECASE):
                            db_type = SQLInjectionDetector.detect_database_type(
                                test_response.text, test_response.headers
                            )
                            return {
                                'vulnerable': True,
                                'technique': 'Error-based',
                                'payload': payload,
                                'database_type': db_type,
                                'error_detected': True
                            }
        except Exception as e:
            logger.debug(f"Error-based test error: {str(e)}")
        
        return {'vulnerable': False, 'technique': 'Error-based'}
    
    @staticmethod
    def test_union_based(url, param_name, original_value):
        """Test union-based SQL injection"""
        union_payloads = SQLInjectionDetector.UNION_BASED_PAYLOADS[:5]
        
        try:
            baseline_response = requests.get(url, timeout=10, allow_redirects=False)
            baseline_text = baseline_response.text.lower()
            
            for payload in union_payloads:
                params, parsed = SQLInjectionDetector.extract_parameters(url)
                if param_name in params:
                    params[param_name] = [payload]
                    test_url = SQLInjectionDetector.build_url(url, params)
                    
                    test_response = requests.get(test_url, timeout=10, allow_redirects=False)
                    test_text = test_response.text.lower()
                    
                    # Check for union injection indicators
                    if 'union' in test_text or test_response.status_code == 200:
                        # Check if response is significantly different
                        if len(test_text) != len(baseline_text):
                            return {
                                'vulnerable': True,
                                'technique': 'Union-based',
                                'payload': payload,
                                'status_code': test_response.status_code
                            }
        except Exception as e:
            logger.debug(f"Union-based test error: {str(e)}")
        
        return {'vulnerable': False, 'technique': 'Union-based'}
    
    @staticmethod
    def check_suspicious_patterns(url):
        """Check for suspicious patterns that might indicate SQL injection attempts"""
        suspicious_patterns = [
            r"['\"]\s*(or|and)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r"union\s+select",
            r"exec\s*\(",
            r"waitfor\s+delay",
            r"sleep\s*\(",
            r"pg_sleep\s*\(",
            r"benchmark\s*\(",
            r"load_file\s*\(",
            r"into\s+outfile",
            r"information_schema",
        ]
        
        found_patterns = []
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                found_patterns.append(pattern)
        
        return found_patterns
    
    @staticmethod
    def perform_sql_injection_scan(target_url, scan_type):
        """
        Perform comprehensive SQL injection scan using multiple detection techniques
        """
        results = {
            'target': target_url,
            'scan_type': scan_type,
            'vulnerabilities': [],
            'tested_parameters': [],
            'database_type': [],
            'techniques_tested': [],
            'overall_status': 'not_vulnerable',
            'confidence': 'low',
            'suspicious_patterns': [],
            'scan_timestamp': datetime.now().isoformat()
        }
        
        try:
            # First, check for suspicious patterns in the URL itself
            suspicious = SQLInjectionDetector.check_suspicious_patterns(target_url)
            if suspicious:
                results['suspicious_patterns'] = suspicious
                results['confidence'] = 'medium'  # Raise confidence if suspicious patterns found
            
            # Parse URL and extract parameters
            params, parsed = SQLInjectionDetector.extract_parameters(target_url)
            
            if not params:
                # If no GET parameters, check if URL itself looks suspicious
                if suspicious:
                    results['message'] = 'No GET parameters found, but suspicious patterns detected in URL.'
                else:
                    results['message'] = 'No GET parameters found. POST-based testing not implemented in this version.'
                return results
            
            # Test each parameter
            for param_name, param_values in params.items():
                original_value = param_values[0] if param_values else ''
                
                param_results = {
                    'parameter': param_name,
                    'original_value': original_value,
                    'tests': []
                }
                
                # Run all test techniques
                techniques = [
                    SQLInjectionDetector.test_boolean_based,
                    SQLInjectionDetector.test_time_based,
                    SQLInjectionDetector.test_error_based,
                    SQLInjectionDetector.test_union_based,
                ]
                
                for technique_func in techniques:
                    try:
                        test_result = technique_func(target_url, param_name, original_value)
                        param_results['tests'].append(test_result)
                        results['techniques_tested'].append(test_result['technique'])
                        
                        if test_result.get('vulnerable'):
                            results['vulnerabilities'].append({
                                'parameter': param_name,
                                'technique': test_result['technique'],
                                'payload': test_result.get('payload', ''),
                                'details': test_result
                            })
                            results['overall_status'] = 'vulnerable'
                            
                            # Detect database type from error-based results
                            if 'database_type' in test_result:
                                results['database_type'].extend(test_result['database_type'])
                    except Exception as e:
                        logger.debug(f"Technique {technique_func.__name__} error: {str(e)}")
                
                results['tested_parameters'].append(param_results)
            
            # Determine confidence level
            if results['vulnerabilities']:
                if len(results['vulnerabilities']) >= 2:
                    results['confidence'] = 'high'
                elif any(v['technique'] == 'Error-based' for v in results['vulnerabilities']):
                    results['confidence'] = 'high'
                else:
                    results['confidence'] = 'medium'
            
            # Remove duplicates from database_type
            results['database_type'] = list(set(results['database_type']))
            results['techniques_tested'] = list(set(results['techniques_tested']))
            
            # Additional heuristic: if multiple techniques found vulnerabilities, increase confidence
            if len(results['vulnerabilities']) > 0:
                unique_techniques = set(v['technique'] for v in results['vulnerabilities'])
                if len(unique_techniques) >= 2:
                    results['confidence'] = 'high'
            
            # Add summary statistics
            results['summary'] = {
                'total_parameters': len(params),
                'vulnerable_parameters': len(results['vulnerabilities']),
                'techniques_used': len(results['techniques_tested']),
                'databases_detected': len(results['database_type'])
            }
            
        except Exception as e:
            logger.error(f"SQL injection scan error: {str(e)}")
            results['error'] = str(e)
            results['overall_status'] = 'error'
        
        return results

class ScanManager:
    """
    Manages the scanning logic, including port scanning and vulnerability detection.
    This class provides static methods to perform different parts of the scanning process.
    """
    @staticmethod
    def perform_sqlmap_scan(scan_id: str, target: str, scan_type: str):
        """
        Perform custom SQL injection scan using our advanced detection algorithms
        Replaces sqlmap with pure logic-based detection
        """
        try:
            logger.info(f"Starting SQL injection scan for {target} (scan_id: {scan_id})")
            
            # Update scan status
            scan = scan_results.get(scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return
            
            # Determine scan depth based on scan_type
            scan_depth_map = {
                ScanType.QUICK: 'quick',
                ScanType.STANDARD: 'standard',
                ScanType.COMPREHENSIVE: 'comprehensive'
            }
            depth = scan_depth_map.get(scan_type, 'standard')
            
            # Perform the SQL injection scan
            scan_result = SQLInjectionDetector.perform_sql_injection_scan(target, depth)
            
            # Format results similar to sqlmap output structure
            formatted_result = {
                'status': 'terminated',
                'success': True,
                'data': {
                    'target': {
                        'url': target,
                        'data': None
                    },
                    'technique': scan_result.get('techniques_tested', []),
                    'dbms': scan_result.get('database_type', ['Unknown']),
                    'dbms_version': None,
                    'vulnerable': scan_result.get('overall_status') == 'vulnerable',
                    'confidence': scan_result.get('confidence', 'low'),
                    'payloads': [
                        {
                            'parameter': vuln['parameter'],
                            'technique': vuln['technique'],
                            'payload': vuln['payload']
                        }
                        for vuln in scan_result.get('vulnerabilities', [])
                    ],
                    'injection': scan_result.get('vulnerabilities', []),
                    'tested_parameters': scan_result.get('tested_parameters', []),
                    'scan_details': {
                        'total_parameters_tested': len(scan_result.get('tested_parameters', [])),
                        'vulnerable_parameters': len(scan_result.get('vulnerabilities', [])),
                        'techniques_used': scan_result.get('techniques_tested', []),
                        'database_detected': scan_result.get('database_type', [])
                    }
                }
            }
            
            # Update scan result
            scan.status = ScanStatus.COMPLETED
            scan.sqlmapResult = formatted_result
            
            # Also add vulnerabilities to the scan object
            if scan_result.get('vulnerabilities'):
                sql_vulns = []
                for vuln in scan_result['vulnerabilities']:
                    severity = 'High' if vuln['technique'] in ['Error-based', 'Time-based'] else 'Medium'
                    sql_vulns.append(Vulnerability(
                        name=f"SQL Injection - {vuln['technique']}",
                        severity=severity,
                        description=f"SQL injection vulnerability detected in parameter '{vuln['parameter']}' using {vuln['technique']} technique. Payload: {vuln.get('payload', 'N/A')}",
                        solution="Use parameterized queries/prepared statements. Validate and sanitize all user inputs. Implement proper input validation and output encoding."
                    ))
                scan.vulnerabilities = sql_vulns
            
            scan_results[scan_id] = scan
            logger.info(f"SQL injection scan completed for {target}")
            
        except Exception as e:
            logger.error(f"Error during SQL injection scan: {str(e)}")
            scan = scan_results.get(scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.rawOutput = str(e)
                scan_results[scan_id] = scan
    @staticmethod
    def scan_port(target: str, port: int, timeout: float = 1.0) -> Optional[PortInfo]:
        """
        Scans a single port on the target host to determine if it's open.

        Args:
            target: The IP address or hostname of the target.
            port: The port number to scan.
            timeout: The maximum time in seconds to wait for a connection attempt.

        Returns:
            An Optional[PortInfo] object if the port is open, otherwise None.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                service = SERVICE_MAP.get(port, "unknown")
                return PortInfo(
                    port=port,
                    state="open",
                    service=service
                )
            return None
        except Exception as e:
            logger.error(f"Error scanning port {port}: {str(e)}")
            return None

    @staticmethod
    def run_port_scan(target: str, scan_type: ScanType) -> List[PortInfo]:
        """
        Executes a port scan against the target based on the specified scan type.
        This method uses a ThreadPoolExecutor to perform concurrent port scans.

        Args:
            target: The IP address or hostname of the target.
            scan_type: The type of scan to perform (Quick, Standard, Comprehensive),
                       which determines the range of ports to scan.

        Returns:
            A list of PortInfo objects for all open ports found.

        Raises:
            Exception: If an error occurs during the port scanning process.
        """
        try:
            # Select ports based on scan type
            ports_to_scan = {
                ScanType.QUICK: COMMON_PORTS,
                ScanType.STANDARD: STANDARD_PORTS,
                ScanType.COMPREHENSIVE: COMPREHENSIVE_PORTS
            }[scan_type]
            
            open_ports = []
            
            # Use ThreadPoolExecutor for parallel scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                # Create future to port mapping
                future_to_port = {
                    executor.submit(ScanManager.scan_port, target, port): port 
                    for port in ports_to_scan
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_port):
                    result = future.result()
                    if result:
                        open_ports.append(result)
            
            return open_ports
            
        except Exception as e:
            logger.error(f"Error during port scan: {str(e)}")
            raise

    @staticmethod
    async def perform_scan(scan_id: str, target: str, scan_type: ScanType, background_tasks: BackgroundTasks):
        """
        Performs the complete vulnerability scan process asynchronously.
        This includes port scanning and a basic vulnerability analysis based on open ports.

        Args:
            scan_id: The unique identifier for the current scan.
            target: The IP address or hostname of the target.
            scan_type: The type of scan to perform.
            background_tasks: FastAPI's BackgroundTasks object for running tasks in the background.
        """
        try:
            # Update scan status to in progress
            scan_results[scan_id].status = ScanStatus.IN_PROGRESS
            print("\nInitial scan state:")
            print(scan_results[scan_id].json(indent=2))
            
            # Run port scan
            ports = ScanManager.run_port_scan(target, scan_type)
            scan_results[scan_id].openPorts = ports
            print("\nAfter port scan:")
            print(scan_results[scan_id].json(indent=2))
            
            # Add some mock vulnerabilities based on scan type
            vulnerabilities = []
            # Analyze open ports to find real vulnerabilities
            for port_info in ports:
                port = port_info.port
                service = SERVICE_MAP.get(port, "unknown")
                
                if port == 21:
                    vulnerabilities.append(Vulnerability(
                        name="FTP Anonymous Login",
                        severity="Medium",
                        description="FTP service is running and may allow anonymous login, which could lead to unauthorized access.",
                        solution="Disable anonymous login or secure FTP server with strong authentication."
                    ))
                elif port == 23:
                    vulnerabilities.append(Vulnerability(
                        name="Telnet Service Detected",
                        severity="High",
                        description="Telnet is an insecure protocol that transmits data in plaintext and is vulnerable to interception.",
                        solution="Disable Telnet and use SSH instead."
                    ))
                elif port in [80, 8080, 8000, 8888]:
                    vulnerabilities.append(Vulnerability(
                        name=f"HTTP Service Running on Port {port}",
                        severity="Medium",
                        description="HTTP service detected, possibly outdated or misconfigured, may be vulnerable to various attacks like XSS or outdated server exploits.",
                        solution="Ensure HTTP servers are up to date and properly configured with security headers."
                    ))
                elif port in [443, 8443, 9443]:
                    vulnerabilities.append(Vulnerability(
                        name="Weak SSL/TLS Configuration",
                        severity="High",
                        description="SSL/TLS configuration allows weak or deprecated cipher suites.",
                        solution="Configure the server to use strong and modern TLS protocols and cipher suites."
                    ))
                elif port == 3306:
                    vulnerabilities.append(Vulnerability(
                        name="MySQL Database Exposure",
                        severity="High",
                        description="MySQL service is exposed and may be vulnerable to brute-force attacks or default credentials.",
                        solution="Restrict access, use strong passwords, and consider firewall rules."
                    ))
                elif port == 3389:
                    vulnerabilities.append(Vulnerability(
                        name="Remote Desktop Protocol Exposure",
                        severity="Critical",
                        description="RDP service exposed, which is commonly targeted by brute force and ransomware attacks.",
                        solution="Limit RDP exposure via VPN or firewall and use strong authentication."
                    ))
                elif port == 5432:
                    vulnerabilities.append(Vulnerability(
                        name="PostgreSQL Database Exposure",
                        severity="High",
                        description="PostgreSQL service is open and may be vulnerable to unauthorized access or brute-force attacks.",
                        solution="Restrict network access, use strong credentials, and monitor access logs."
                    ))
                elif port == 5900:
                    vulnerabilities.append(Vulnerability(
                        name="VNC Service Detected",
                        severity="Medium",
                        description="VNC service is running and may allow unauthorized remote access if not secured.",
                        solution="Use strong passwords and restrict access."
                    ))
                elif port == 6379:
                    vulnerabilities.append(Vulnerability(
                        name="Redis Unsecured Access",
                        severity="High",
                        description="Redis server is accessible without authentication, which can lead to remote code execution.",
                        solution="Secure Redis by enabling authentication and firewalling the port."
                    ))
                # Add more rules as you want

            # Additional comprehensive scan logic
            if scan_type == ScanType.COMPREHENSIVE:
                # Add general vulnerabilities unrelated to specific ports but to configuration
                vulnerabilities.append(Vulnerability(
                    name="Default Credentials",
                    severity="Critical",
                    description="Services might be using default credentials, exposing the system to compromise.",
                    solution="Change all default passwords immediately."
                ))
                
            scan_results[scan_id].vulnerabilities = vulnerabilities
            scan_results[scan_id].status = ScanStatus.COMPLETED
            
            print("\nFinal scan results:")
            print(scan_results[scan_id].json(indent=2))
            
            logger.info(f"Scan completed for {target} with {len(ports)} open ports and {len(vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            scan_results[scan_id].status = ScanStatus.FAILED
            scan_results[scan_id].rawOutput = str(e)
            print("\nScan failed:")
            print(scan_results[scan_id].json(indent=2))

@app.post("/scan", response_model=Scan)
async def create_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Initiates a new vulnerability scan against the specified target.
    The scan runs as a background task, and an initial scan object is returned immediately.

    Args:
        scan_request: A ScanRequest object containing the target and scan type.
        background_tasks: FastAPI's BackgroundTasks object for running tasks in the background.

    Returns:
        A Scan object representing the newly created scan, with its initial status.

    Raises:
        HTTPException: If an internal server error occurs during scan creation.
    """
    try:
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Create initial scan result
        scan = Scan(
            id=scan_id,
            target=scan_request.target,
            scanType=scan_request.scanType,
            timestamp=datetime.now().isoformat(),
            status=ScanStatus.IN_PROGRESS
        )
        
        # Store the scan
        scan_results[scan_id] = scan
        
        print("\nCreated new scan:")
        print(scan.json(indent=2))
        
        # Start scan in background
        background_tasks.add_task(
            ScanManager.perform_scan,
            scan_id,
            scan_request.target,
            scan_request.scanType,
            background_tasks
        )
        
        return scan
        
    except Exception as e:
        logger.error(f"Error creating scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scan/{scan_id}", response_model=Scan)
async def get_scan_status(scan_id: str):
    """
    Retrieves the status and results of a previously initiated scan.

    Args:
        scan_id: The unique identifier of the scan to retrieve.

    Returns:
        A Scan object containing the current status, open ports, and vulnerabilities found.

    Raises:
        HTTPException: If the scan ID is not found (404).
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scan_results[scan_id]
    print(f"\nGetting scan status for {scan_id}:")
    print(scan.json(indent=2))
    return scan
@app.get("/")
async def root():
    """
    Root endpoint that returns a welcome message.
    """
    return {"message": "Our Agile-Project server is running"}

@app.get("/health")
async def health_check():
    """
    Health check endpoint to verify the API is running.
    """
    return {"status": "healthy"}


class DirectoryBruteForcer:
    """
    Advanced Directory and File Brute-Forcing Engine
    Implements multiple techniques: Status code analysis, Response size filtering,
    Content analysis, Extension guessing, and Pattern matching
    """
    
    # Common file extensions to test
    COMMON_EXTENSIONS = [
        '', 'html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'js', 'css',
        'txt', 'xml', 'json', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
        'zip', 'tar', 'gz', 'bak', 'old', 'backup', 'log', 'sql',
        'conf', 'config', 'ini', 'env', 'yaml', 'yml'
    ]
    
    # Common directory patterns
    COMMON_DIRECTORIES = [
        'admin', 'administrator', 'api', 'assets', 'backup', 'backups',
        'bin', 'config', 'database', 'db', 'docs', 'documentation',
        'files', 'images', 'img', 'includes', 'inc', 'js', 'css',
        'lib', 'library', 'logs', 'media', 'old', 'private', 'public',
        'resources', 'src', 'static', 'temp', 'tmp', 'test', 'tests',
        'uploads', 'upload', 'vendor', 'www', 'web', 'webroot'
    ]
    
    # Status codes that typically indicate valid resources
    VALID_STATUS_CODES = [200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 405]
    
    # Status codes that indicate the resource doesn't exist
    INVALID_STATUS_CODES = [404]
    
    @staticmethod
    def load_wordlist(wordlist_path: str = "ressources/wordlist.txt") -> List[str]:
        """Load wordlist from file"""
        try:
            with open(wordlist_path, "r", encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            logger.warning(f"Wordlist not found at {wordlist_path}, using default common words")
            return DirectoryBruteForcer.COMMON_DIRECTORIES
        except Exception as e:
            logger.error(f"Error loading wordlist: {str(e)}")
            return DirectoryBruteForcer.COMMON_DIRECTORIES
    
    @staticmethod
    def check_endpoint(base_url: str, endpoint: str, extensions: List[str] = None, baseline_size: int = 0) -> Optional[Dict]:
        """
        Check if an endpoint exists by making HTTP request
        Returns dict with endpoint info if found, None otherwise
        """
        if extensions is None:
            extensions = ['']
        
        base_url = base_url.rstrip('/')
        endpoint = endpoint.lstrip('/')
        
        results = []
        
        # Test variations: with extension, without extension, with trailing slash (for directories)
        test_variations = []
        
        for ext in extensions:
            if ext:
                test_variations.append((f"{base_url}/{endpoint}.{ext}", endpoint + f'.{ext}'))
            else:
                # Test without extension
                test_variations.append((f"{base_url}/{endpoint}", endpoint))
                # Test with trailing slash (for directories)
                test_variations.append((f"{base_url}/{endpoint}/", endpoint + '/'))
        
        for test_path, display_name in test_variations:
            try:
                # First try without following redirects
                response = requests.get(
                    test_path,
                    timeout=8,
                    allow_redirects=False,
                    verify=False,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                
                status = response.status_code
                content_length = len(response.content)
                content_type = response.headers.get('Content-Type', 'unknown')
                
                # Check if this is a valid endpoint
                if status in DirectoryBruteForcer.VALID_STATUS_CODES:
                    # More lenient size filtering - accept if size differs by more than 10% or is significantly different
                    size_diff_percent = abs(content_length - baseline_size) / max(baseline_size, 1) * 100
                    
                    # Accept if:
                    # 1. Status is 200 (definitely valid)
                    # 2. Status is redirect (301, 302, etc.) - valid endpoint
                    # 3. Status is 401/403 (exists but protected)
                    # 4. Size differs significantly (more than 10% or absolute difference > 100 bytes)
                    if (status == 200 or 
                        status in [301, 302, 303, 307, 308] or 
                        status in [401, 403] or
                        (baseline_size > 0 and (size_diff_percent > 10 or abs(content_length - baseline_size) > 100)) or
                        (baseline_size == 0 and content_length > 0)):
                        
                        # Get redirect location if applicable
                        redirect_location = response.headers.get('Location', '')
                        
                        results.append({
                            'url': test_path,
                            'status': status,
                            'size': content_length,
                            'content_type': content_type,
                            'endpoint': display_name,
                            'redirect': redirect_location if status in [301, 302, 303, 307, 308] else None
                        })
                        
                # Also try with redirects enabled to catch endpoints that redirect
                if status in [301, 302, 303, 307, 308]:
                    try:
                        redirect_response = requests.get(
                            test_path,
                            timeout=8,
                            allow_redirects=True,
                            verify=False,
                            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                        )
                        if redirect_response.status_code == 200:
                            results.append({
                                'url': test_path,
                                'status': status,
                                'size': len(redirect_response.content),
                                'content_type': redirect_response.headers.get('Content-Type', 'unknown'),
                                'endpoint': display_name,
                                'redirect': redirect_response.url
                            })
                    except:
                        pass
                    
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.RequestException as e:
                # Log but continue
                logger.debug(f"Request error for {test_path}: {str(e)}")
                continue
        
        # Return the first valid result, or None
        return results[0] if results else None
    
    @staticmethod
    def analyze_response_pattern(base_url: str) -> Dict:
        """
        Analyze baseline response patterns to filter false positives
        Test multiple fake endpoints to get accurate baseline
        """
        try:
            # Test multiple non-existent endpoints to get average baseline
            fake_endpoints = [
                f"nonexistent-{random.randint(10000, 99999)}",
                f"fake-{random.randint(10000, 99999)}",
                f"test-{random.randint(10000, 99999)}"
            ]
            
            sizes = []
            statuses = []
            
            for fake_endpoint in fake_endpoints:
                try:
                    baseline_response = requests.get(
                        f"{base_url}/{fake_endpoint}",
                        timeout=5,
                        allow_redirects=False,
                        verify=False,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                    )
                    sizes.append(len(baseline_response.content))
                    statuses.append(baseline_response.status_code)
                except:
                    continue
            
            # Use average size, or 0 if no samples
            avg_size = sum(sizes) // len(sizes) if sizes else 0
            most_common_status = max(set(statuses), key=statuses.count) if statuses else 404
            
            return {
                'not_found_status': most_common_status,
                'not_found_size': avg_size,
                'samples': len(sizes)
            }
        except Exception as e:
            logger.debug(f"Baseline analysis error: {str(e)}")
            return {'not_found_status': 404, 'not_found_size': 0, 'samples': 0}
    
    @staticmethod
    def perform_directory_bruteforce(
        base_url: str,
        wordlist: List[str] = None,
        extensions: List[str] = None,
        max_workers: int = 50,
        scan_type: str = "standard"
    ) -> Dict:
        """
        Perform comprehensive directory and file brute-forcing
        """
        results = {
            'target': base_url,
            'scan_type': scan_type,
            'found_endpoints': [],
            'total_tested': 0,
            'scan_timestamp': datetime.now().isoformat(),
            'statistics': {
                'by_status_code': {},
                'by_extension': {},
                'largest_response': None,
                'smallest_response': None
            }
        }
        
        try:
            # Load wordlist
            if wordlist is None:
                wordlist = DirectoryBruteForcer.load_wordlist()
            
            # Limit wordlist based on scan type
            if scan_type == "quick":
                wordlist = wordlist[:200]  # Top 200 (increased)
            elif scan_type == "standard":
                wordlist = wordlist[:1000]  # Top 1000 (increased)
            # comprehensive uses full wordlist
            
            logger.info(f"Loaded {len(wordlist)} words from wordlist for {scan_type} scan")
            
            # Set extensions to test
            if extensions is None:
                if scan_type == "quick":
                    extensions = ['', 'html', 'htm', 'php', 'txt', 'js', 'css']
                elif scan_type == "standard":
                    extensions = DirectoryBruteForcer.COMMON_EXTENSIONS[:15]
                else:
                    extensions = DirectoryBruteForcer.COMMON_EXTENSIONS
            
            logger.info(f"Testing with {len(extensions)} extensions: {extensions[:5]}...")
            
            # Analyze baseline - get multiple samples for better accuracy
            baseline = DirectoryBruteForcer.analyze_response_pattern(base_url)
            not_found_size = baseline.get('not_found_size', 0)
            not_found_status = baseline.get('not_found_status', 404)
            
            logger.info(f"Baseline analysis: 404 size={not_found_size}, status={not_found_status}")
            
            # Generate test combinations - test common paths first, then wordlist
            test_cases = []
            
            # First, test very common files/directories
            common_paths = [
                'admin', 'administrator', 'api', 'assets', 'backup', 'backups', 
                'config', 'configuration', 'images', 'img', 'js', 'css', 
                'includes', 'inc', 'uploads', 'upload', 'files', 'file',
                'index', 'home', 'main', 'test', 'tests', 'dev', 'development',
                'phpinfo', 'info', 'robots.txt', 'sitemap.xml', '.env', '.git',
                'wp-admin', 'wp-content', 'wp-includes', 'wp-config.php',
                'database', 'db', 'sql', 'logs', 'log', 'access.log', 'error.log'
            ]
            
            for path in common_paths:
                # Test as directory (no extension)
                test_cases.append((path, ''))
                # Test with common extensions
                if path not in ['robots.txt', 'sitemap.xml', '.env', '.git', 'wp-config.php', 'access.log', 'error.log']:
                    for ext in ['php', 'html', 'txt', 'xml']:
                        if not path.endswith(ext):
                            test_cases.append((path, ext))
            
            # Then test wordlist with extensions
            for word in wordlist:
                # Skip if already tested in common paths
                if word.lower() not in [p.lower() for p in common_paths]:
                    for ext in extensions:
                        test_cases.append((word, ext))
            
            results['total_tested'] = len(test_cases)
            logger.info(f"Testing {len(test_cases)} combinations against {base_url}")
            
            # Perform concurrent scanning with progress tracking
            found_endpoints = []
            seen_urls = set()  # Avoid duplicates
            completed = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_case = {
                    executor.submit(
                        DirectoryBruteForcer.check_endpoint,
                        base_url,
                        word,
                        [ext] if ext else [''],
                        not_found_size
                    ): (word, ext)
                    for word, ext in test_cases
                }
                
                for future in concurrent.futures.as_completed(future_to_case):
                    completed += 1
                    if completed % 50 == 0:
                        logger.info(f"Progress: {completed}/{len(test_cases)} tested, {len(found_endpoints)} found")
                    
                    try:
                        result = future.result(timeout=10)
                        if result:
                            # Avoid duplicates
                            if result['url'] not in seen_urls:
                                seen_urls.add(result['url'])
                                found_endpoints.append(result)
                                
                                # Update statistics
                                status = result['status']
                                results['statistics']['by_status_code'][status] = \
                                    results['statistics']['by_status_code'].get(status, 0) + 1
                                
                                # Extract extension
                                endpoint_parts = result['endpoint'].split('.')
                                if len(endpoint_parts) > 1:
                                    ext_used = endpoint_parts[-1]
                                elif result['endpoint'].endswith('/'):
                                    ext_used = 'directory'
                                else:
                                    ext_used = 'no-ext'
                                
                                results['statistics']['by_extension'][ext_used] = \
                                    results['statistics']['by_extension'].get(ext_used, 0) + 1
                                
                                # Track largest/smallest
                                if not results['statistics']['largest_response'] or \
                                   result['size'] > results['statistics']['largest_response']['size']:
                                    results['statistics']['largest_response'] = result
                                
                                if not results['statistics']['smallest_response'] or \
                                   result['size'] < results['statistics']['smallest_response']['size']:
                                    results['statistics']['smallest_response'] = result
                                    
                                logger.info(f"Found: {result['url']} [{result['status']}] ({result['size']} bytes)")
                                    
                    except concurrent.futures.TimeoutError:
                        logger.debug("Request timeout")
                        continue
                    except Exception as e:
                        logger.debug(f"Error checking endpoint: {str(e)}")
                        continue
            
            # Sort by status code (200s first, then redirects, then auth errors)
            found_endpoints.sort(key=lambda x: (
                0 if x['status'] == 200 else (1 if x['status'] in [301, 302, 303, 307, 308] else 2),
                -x['size']  # Larger responses first
            ))
            
            results['found_endpoints'] = found_endpoints
            results['total_found'] = len(found_endpoints)
            
            logger.info(f"Scan completed: Found {len(found_endpoints)} endpoints out of {len(test_cases)} tested")
            
        except Exception as e:
            logger.error(f"Directory bruteforce error: {str(e)}")
            results['error'] = str(e)
        
        return results
########################this is my modification######################
@app.post("/scan/sqlmap", response_model=Scan)
async def create_sqlmap_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Initiate a new SQL injection scan using our custom detection engine.
    The scan runs in background and returns initial scan object immediately.
    Uses advanced algorithms: Boolean-based, Time-based, Error-based, and Union-based detection.
    """
    try:
        # Generate scan id 
        scan_id = str(uuid.uuid4())
        # Create initial scan result 
        scan = Scan(
            id=scan_id,
            target=scan_request.target,
            scanType=scan_request.scanType,
            timestamp=datetime.now().isoformat(),
            status=ScanStatus.IN_PROGRESS,
        )
        # Store the scan
        scan_results[scan_id] = scan
        # Start the scan in background 
        background_tasks.add_task(
            ScanManager.perform_sqlmap_scan,
            scan_id,
            scan_request.target,
            scan_request.scanType,
        )
        return scan
    except Exception as e:
        logger.error(f"Error creating SQL injection scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
@app.get("/scan/sqlmap/{scan_id}", response_model=Scan)
async def get_sqlmap_scan(scan_id: str):
    """
    Returns the current state (status + JSON result) of a scan.
    """
    scan = scan_results.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 


