import requests
from .rules import SECURITY_HEADERS, INFORMATION_DISCLOSURE_HEADERS

class HeaderScanner:
    """
    Handles the HTTP communication and parsing of headers against defined rules.
    """
    def __init__(self, url, timeout=10, verify_ssl=True):
        # Gracefully handle missing URL schemes
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
            
        self.url = url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.headers = {}

    def fetch_headers(self):
        """
        Executes a GET request to harvest response headers.
        Returns a tuple of (Success: bool, Status_Code_or_Error: str)
        """
        try:
            # Using a descriptive user agent to identify ourselves and bypass basic blocks
            req_headers = {"User-Agent": "HeaderHound-Security-Scanner/1.0"}
            response = requests.get(
                self.url, 
                headers=req_headers, 
                timeout=self.timeout, 
                verify=self.verify_ssl,
                allow_redirects=True
            )
            self.headers = response.headers
            return True, response.status_code
        except requests.exceptions.SSLError:
            return False, "SSL/TLS Verification Failed. Try running with --no-verify"
        except requests.exceptions.RequestException as e:
            return False, str(e)

    def analyze(self):
        """
        Analyzes the fetched headers against the definitions in rules.py.
        Returns a structured dictionary of passed, failed, and warning findings.
        """
        results = {
            "passed": [],
            "failed": [],
            "warnings": []
        }
        
        # 1. Check for missing or misconfigured security headers
        for header, rule in SECURITY_HEADERS.items():
            # Standardize lookup as headers are case-insensitive
            matched_key = next((k for k in self.headers.keys() if k.lower() == header.lower()), None)
            
            if matched_key:
                val = self.headers[matched_key]
                if "expected" in rule and rule["expected"].lower() != val.lower():
                    results["failed"].append({
                        "header": header,
                        "issue": f"Misconfigured. Expected '{rule['expected']}', got '{val}'",
                        "recommendation": rule["recommendation"]
                    })
                else:
                    results["passed"].append({
                        "header": header,
                        "value": val
                    })
            elif rule.get("required"):
                results["failed"].append({
                    "header": header,
                    "issue": "Missing security header",
                    "recommendation": rule["recommendation"]
                })

        # 2. Check for information disclosure headers (e.g. Server: nginx/1.14.0)
        for header in INFORMATION_DISCLOSURE_HEADERS:
            matched_key = next((k for k in self.headers.keys() if k.lower() == header.lower()), None)
            if matched_key:
                results["warnings"].append({
                    "header": header,
                    "issue": f"Information disclosure: '{self.headers[matched_key]}'",
                    "recommendation": "Remove or obfuscate this header to hide backend technology."
                })
                
        return results
