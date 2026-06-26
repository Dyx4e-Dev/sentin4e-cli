# mypy: ignore-errors
from typing import Dict, Tuple

def detect_waf(headers: Dict[str, str], cookies: Dict[str, str] = None) -> str:
    """
    Detect the presence of a Web Application Firewall.
    """
    if cookies is None:
        cookies = {}
        
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    lower_cookies = {k.lower(): str(v).lower() for k, v in cookies.items()}
    
    waf_signatures = {
        'CLOUDFLARE': lambda h, c: 'cloudflare' in h.get('server', '') or '__cfduid' in c or 'cf_clearance' in c,
        'AKAMAI': lambda h, c: 'akamai' in h.get('server', '') or 'x-akamai-request-id' in h,
        'SUCURI': lambda h, c: 'sucuri/cloudproxy' in h.get('server', '') or 'x-sucuri-id' in h,
        'AWS_WAF': lambda h, c: 'awselb' in h.get('server', '') or 'x-amz-cf-id' in h,
        'IMPERVA': lambda h, c: 'incapsula' in h.get('x-cdn', '') or 'imperva' in h.get('server', '')
    }
    
    for waf_name, check_func in waf_signatures.items():
        if check_func(lower_headers, lower_cookies):
            return waf_name
            
    return "NOT_DETECTED"

def is_parked_domain(html_body: str) -> bool:
    """
    Detects if the target is a parked domain or default registrar page based on the HTML body.
    """
    if not html_body:
        return False
        
    body_lower = html_body.lower()
    
    parked_signatures = [
        "this domain is registered at",
        "domain is parked",
        "this website is parked",
        "registered at namecheap.com",
        "default web page",
        "welcome to nginx",
        "it works!",
        "this domain has been registered",
        "godaddy.com"
    ]
    
    # We only check the first 5000 characters to prevent huge CPU spikes on large pages
    body_snippet = body_lower[:5000]
    
    for sig in parked_signatures:
        if sig in body_snippet:
            return True
            
    return False

def analyze_response_context(status_code: int, is_parked: bool = False) -> Tuple[str, str]:
    """
    Analyze the HTTP context to determine the validity of the scan.
    """
    if is_parked:
        return "PARKED_DOMAIN", "This appears to be a parked domain or default server page. Security headers may not reflect a real application."
        
    if 200 <= status_code < 400:
        return "FULL_SCAN", "Valid application response."
    elif status_code in (401, 403):
        return "PARTIAL_SCAN", f"Access restricted ({status_code}). Missing headers might be expected."
    elif status_code >= 500:
        return "ABORT", f"Server error ({status_code}). Scan results would be inaccurate."
    else:
        return "UNKNOWN", f"Unexpected status code: {status_code}"
