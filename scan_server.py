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
SQLMAP_API_URL = "http://127.0.0.1:8775"

class ScanManager:
    """
    Manages the scanning logic, including port scanning and vulnerability detection.
    This class provides static methods to perform different parts of the scanning process.
    """
    #################my modification#################
    @staticmethod
    def _sqlmap_task(target:str) ->str:
        #create a new sql map task
        r=requests.get(f"{SQLMAP_API_URL}/task/new")
        r.raise_for_status()
        task_id=r.json()["taskid"]
        return task_id
    @staticmethod
    def start_sqlmap_scan(task_id:str, target:str):
        # start scan with basic options
        data = {
            "url": target,
            "risk": 2,
            "level": 2
        }
        r=requests.post(f"{SQLMAP_API_URL}/scan/{task_id}/start", json=data)
        r.raise_for_status()
    @staticmethod
     def _get_sqlmap_status(task_id: str) -> str:
        r = requests.get(f"{SQLMAP_API_URL}/scan/{task_id}/status")
        r.raise_for_status()
        return r.json().get("status")  # "running" or "terminated"
    @staticmethod
    def _get_sqlmap_data(task_id: str):
        # this endpoint returns vulnerabilities and other data as JSON
        r = requests.get(f"{SQLMAP_API_URL}/scan/{task_id}/data")
        r.raise_for_status()
        return r.json()
    @staticmethod
    def perform_sqlmap_scan(scan_id: str, target: str, scan_type: str):
        try:
            task_id = ScanManager._sqlmap_task(target)
            ScanManager.start_sqlmap_scan(task_id, target)

            # poll until sqlmap finishes
            while True:
                status = ScanManager._get_sqlmap_status(task_id)
                if status == "terminated":
                    break
                #simple sleep to avoid hammering the api
                asyncio.sleep(1)

            data = ScanManager._get_sqlmap_data(task_id)

            # update stored scan result
            scan = scan_results[scan_id]
            scan.status = ScanStatus.COMPLETED
            scan.sqlmapResult = data  # already JSON-serializable
            scan_results[scan_id] = scan

        except Exception as e:
            scan = scan_results.get(scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.rawOutput = str(e)
                scan_results[scan_id] = scan
    ######################### modification ends here in this class ####################
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
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 


########################this is my modification######################
@app.post("/scan/sqlmap",response_model=Scan)
async def create_sqlmap_scan(scan_request: ScanRequest,background_tasks: BackgroundTasks):
    """
    Initiate a new sqlmap scan in background and returns initial scan object
    """
    try:
        # Generate scan id 
        scan_id = str(uuid.uuid4())
        # Create initial scan result 
        scan = Scan(
            id= scan_id,
            target = scan_request.target,
            scan_type= scan_request.scan_type,
            timestamp = datetime.now().isoformat(),
            status = ScanStatus.IN_PROGRESS,
        )
        # Store the scan
        scan_results[scan_id] = scan
        #start the scan in background 
        background_tasks.add_task(
            ScanManager.perform_sqlmap_scan,
            scan_id,
            scan_request.target,
            scan_request.scan_type,
        )
        return scan
    except Exception as e:
        raise HTTPException(status_code=500,detail=str(e))
@app.get("/scan/sqlmap/{scan_id}", response_model=Scan)
async def get_sqlmap_scan(scan_id: str):
    """
    Returns the current state (status + JSON result) of a scan.
    """
    scan = scan_results.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan