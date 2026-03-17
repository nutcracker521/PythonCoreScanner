import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
import threading
from concurrent.futures import ThreadPoolExecutor
import sys
import json
from typing import List, Dict, Set

class WebSecurityScanner:


    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


    SECURITY_HEADERS = {
        "Strict-Transport-Security": (HIGH,   "Missing HSTS header"),
        "Content-Security-Policy":   (HIGH,   "Missing Content-Security-Policy header"),
        "X-Frame-Options":           (MEDIUM, "Missing X-Frame-Options header (clickjacking risk)"),
        "X-Content-Type-Options":    (MEDIUM, "Missing X-Content-Type-Options header"),
        "Referrer-Policy":           (LOW,    "Missing Referrer-Policy header"),
        "Permissions-Policy":        (LOW,    "Missing Permissions-Policy header"),
    }

    def __init__(self, target_url: str, max_depth: int = 3, timeout: int = 10):
        self.url        = target_url
        self.max_depth  = max_depth
        self.timeout    = timeout                  

        self.visited_urls:   Set[str]  = set()
        self.vulnerabilities: List[Dict] = []
        self._vuln_keys:     Set[str]  = set()      
        self._lock           = threading.Lock()     

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "WebSecurityScanner/1.0"})

        colorama.init()



    def normalize_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _build_url_with_param(self, url: str, param: str, value: str) -> str:
        """Rebuild a URL replacing a single query parameter value safely."""  # FIX
        parsed  = urllib.parse.urlparse(url)
        params  = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def report_vulnerability(self, vulnerability: Dict) -> None:
        """Thread-safe, deduplicated vulnerability reporting."""  # FIX
        key = json.dumps(
            {k: vulnerability[k] for k in sorted(vulnerability) if k != "pattern"},
            sort_keys=True,
        )
        with self._lock:                            # FIX:
            if key in self._vuln_keys:
                return
            self._vuln_keys.add(key)
            self.vulnerabilities.append(vulnerability)

        severity  = vulnerability.get("severity", "?")
        vuln_type = vulnerability["type"]
        color     = (colorama.Fore.RED   if severity == self.HIGH   else
                     colorama.Fore.YELLOW if severity == self.MEDIUM else
                     colorama.Fore.CYAN)
        print(
            f"{color}[{severity}] {vuln_type} found at "
            f"{vulnerability['url']}{colorama.Style.RESET_ALL}"
        )



    def crawl(self, url: str, depth: int = 0) -> None:
        if depth > self.max_depth or url in self.visited_urls:
            return

        try:
            self.visited_urls.add(url)
            response = self.session.get(url, timeout=self.timeout)  # FIX: timeout
            soup     = BeautifulSoup(response.text, "html.parser")

            for link in soup.find_all("a", href=True):
                next_url = urllib.parse.urljoin(url, link["href"])
                if next_url.startswith(self.url):
                    self.crawl(next_url, depth + 1)

        except Exception as e:
            print(f"Error crawling {url}: {e}")


    def check_sql_injection(self, url: str) -> None:
        sql_payloads = [
            "'",
            "1' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "\" OR \"\"=\"",
        ]
        sql_errors = ["sql", "mysql", "sqlite", "postgresql", "oracle",
                      "syntax error", "unclosed quotation", "odbc"]

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        for param in params:
            for payload in sql_payloads:
                try:
                    target_url = self._build_url_with_param(url, param, payload)  # FIX
                    response   = self.session.get(target_url, timeout=self.timeout)

                    if any(err in response.text.lower() for err in sql_errors):
                        self.report_vulnerability({
                            "type":      "SQL Injection",
                            "severity":  self.HIGH,
                            "url":       url,
                            "parameter": param,
                            "payload":   payload,
                        })
                        break   # one confirmed hit per param is enough

                except Exception as e:
                    print(f"Error testing SQL injection on {url}: {e}")



    def check_xss(self, url: str) -> None:
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><svg onload=alert(1)>",
        ]

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        for param in params:
            for payload in xss_payloads:
                try:
                    target_url = self._build_url_with_param(          # FIX
                        url, param, urllib.parse.quote(payload)
                    )
                    response = self.session.get(target_url, timeout=self.timeout)

                    # FIX: check for reflected payload, NOT sql errors
                    if payload.lower() in response.text.lower() or \
                       urllib.parse.quote(payload).lower() in response.text.lower():
                        self.report_vulnerability({
                            "type":      "Cross-Site Scripting (XSS)",
                            "severity":  self.HIGH,
                            "url":       url,
                            "parameter": param,
                            "payload":   payload,
                        })
                        break

                except Exception as e:
                    print(f"Error testing XSS on {url}: {e}")



    def check_sensitive_info(self, url: str) -> None:
        sensitive_patterns = {
            "email":   (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", self.LOW),
            "phone":   (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",                    self.LOW),
            "ssn":     (r"\b\d{3}-\d{2}-\d{4}\b",                            self.HIGH),
            "api_key": (r"api[_-]?key[_-]?['\"`]([a-zA-Z0-9]{32,45})['\"`]", self.HIGH),
            "aws_key": (r"AKIA[0-9A-Z]{16}",                                  self.HIGH),
            "jwt":     (r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", self.MEDIUM),
        }

        try:
            response = self.session.get(url, timeout=self.timeout)

            for info_type, (pattern, severity) in sensitive_patterns.items():
                for match in re.finditer(pattern, response.text):
                    snippet = match.group(0)[:40]
                    self.report_vulnerability({
                        "type":      "Sensitive Information Exposure",
                        "severity":  severity,
                        "url":       url,
                        "info_type": info_type,
                        "snippet":   snippet,
                    })

        except Exception as e:
            print(f"Error checking sensitive info on {url}: {e}")



    def check_security_headers(self, url: str) -> None:
        """Report missing HTTP security headers."""
        try:
            response = self.session.head(url, timeout=self.timeout, allow_redirects=True)

            for header, (severity, description) in self.SECURITY_HEADERS.items():
                if header not in response.headers:
                    self.report_vulnerability({
                        "type":        "Missing Security Header",
                        "severity":    severity,
                        "url":         url,
                        "header":      header,
                        "description": description,
                    })

        except Exception as e:
            print(f"Error checking security headers on {url}: {e}")


    def check_open_redirect(self, url: str) -> None:
        """Test query parameters that look like redirect targets."""
        redirect_params = {"redirect", "url", "next", "return", "returnto",
                           "return_url", "goto", "target", "dest", "destination"}
        redirect_payload = "https://evil.example.com"

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        for param in params:
            if param.lower() not in redirect_params:
                continue
            try:
                target_url = self._build_url_with_param(url, param, redirect_payload)
                response   = self.session.get(
                    target_url, timeout=self.timeout, allow_redirects=False
                )
                location = response.headers.get("Location", "")
                if redirect_payload in location:
                    self.report_vulnerability({
                        "type":      "Open Redirect",
                        "severity":  self.MEDIUM,
                        "url":       url,
                        "parameter": param,
                        "payload":   redirect_payload,
                    })
            except Exception as e:
                print(f"Error checking open redirect on {url}: {e}")



    def check_directory_traversal(self, url: str) -> None:
        """Test parameters for path-traversal vulnerabilities."""
        traversal_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
        ]
        traversal_signatures = ["root:x:", "[extensions]", "for 16-bit"]

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        for param in params:
            for payload in traversal_payloads:
                try:
                    target_url = self._build_url_with_param(url, param, payload)
                    response   = self.session.get(target_url, timeout=self.timeout)

                    if any(sig in response.text for sig in traversal_signatures):
                        self.report_vulnerability({
                            "type":      "Directory Traversal",
                            "severity":  self.HIGH,
                            "url":       url,
                            "parameter": param,
                            "payload":   payload,
                        })
                        break

                except Exception as e:
                    print(f"Error checking directory traversal on {url}: {e}")


    def scan(self) -> List[Dict]:
        print(
            f"\n{colorama.Fore.BLUE}Starting security scan of "
            f"{self.url}{colorama.Style.RESET_ALL}\n"
        )

        self.crawl(self.url)
        print(f"Crawled {len(self.visited_urls)} URL(s). Running checks...\n")

        checks = [
            self.check_sql_injection,
            self.check_xss,
            self.check_sensitive_info,
            self.check_security_headers,    # NEW
            self.check_open_redirect,       # NEW
            self.check_directory_traversal, # NEW
        ]

        with ThreadPoolExecutor(max_workers=10) as executor:
            for url in self.visited_urls:
                for check in checks:
                    executor.submit(check, url)

        self._print_summary()
        return self.vulnerabilities


    def _print_summary(self) -> None:
        counts = {self.HIGH: 0, self.MEDIUM: 0, self.LOW: 0}
        for v in self.vulnerabilities:
            counts[v.get("severity", self.LOW)] += 1

        print(f"\n{colorama.Fore.BLUE}{'='*50}")
        print("SCAN COMPLETE — SUMMARY")
        print(f"{'='*50}{colorama.Style.RESET_ALL}")
        print(f"{colorama.Fore.RED   }HIGH   : {counts[self.HIGH  ]}{colorama.Style.RESET_ALL}")
        print(f"{colorama.Fore.YELLOW}MEDIUM : {counts[self.MEDIUM]}{colorama.Style.RESET_ALL}")
        print(f"{colorama.Fore.CYAN  }LOW    : {counts[self.LOW   ]}{colorama.Style.RESET_ALL}")
        print(f"Total  : {len(self.vulnerabilities)}\n")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print("Usage: python web_security_scanner.py <target_url> [max_depth]")
        sys.exit(1)

    target_url = sys.argv[1]
    max_depth  = int(sys.argv[2]) if len(sys.argv) == 3 else 3

    scanner = WebSecurityScanner(target_url, max_depth=max_depth)
    results = scanner.scan()
    print(json.dumps(results, indent=2))