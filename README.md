# WAFManis: Protocol-Level WAF Evasion Fuzzing Tool

WAFManis is a **fuzzing framework** designed to test Web Application Firewalls (WAFs) for **protocol-level evasion vulnerabilities**. It automatically sends crafted HTTP requests to WAFs and web applications behind them to identify bypass techniques. This tool helps security professionals test the robustness of WAFs against various payloads such as **SQL Injection**, **XSS**, **NoSQL Injection**, and more.

## Features
- Tests for a variety of **payloads** such as SQL Injection, XSS, Path Traversal, NoSQL Injection, and OS Command Injection.
- Automatically detects **WAF bypass** by comparing responses from the WAF and the web application directly.
- Provides information about the tool and its developers.

## How It Works
WAFs are designed to block malicious requests before they reach the web application. However, differences in how WAFs and web applications parse HTTP requests can result in **evasion vulnerabilities**. This tool sends various crafted HTTP requests to both the WAF and the web application, and if their responses differ, it indicates a **WAF bypass**.

### Payload Categories:
- **SQL Injection**: Common SQLi techniques like UNION SELECT, Blind SQLi, and DROP TABLE.
- **Cross-Site Scripting (XSS)**: Common XSS payloads using `<script>` tags, images, and event handlers.
- **NoSQL Injection**: Payloads targeting NoSQL databases such as MongoDB.
- **XML Injection**: Crafting malicious XML inputs to exploit XXE (XML External Entity) vulnerabilities.
- **Path Traversal**: Exploiting file path vulnerabilities to access restricted files.
- **OS Command Injection**: Injecting shell commands to gain unauthorized access.

## Getting Started

### Prerequisites
- **Python 3.x** installed on your system.
- **Requests** library for Python to send HTTP requests.

You can install the required Python library using:
```bash
pip install requests
git clone https://github.com/mrmtwoj/WAFManis.git
cd wafmanis
```
## Usage
- To use the tool, provide the WAF URL and the Web Application URL behind the WAF:
```bash
python3 wafmanis.py --target http://<waf-ip-address> --app http://<webapp-ip-address>
```
### For example:
```bash
python3 wafmanis.py --target http://192.168.1.10 --app http://192.168.1.20
```
This will test the target WAF and compare its behavior to the web application’s direct response. The script will output whether the WAF successfully blocked the payload or if a bypass was detected.

## Command-Line Arguments
- target: The URL of the WAF you want to test (e.g., http://192.168.1.10).
- app: The URL of the web application behind the WAF (e.g., http://192.168.1.20).
- info: Display tool information, such as the developer name, version.
- about: Display information about the tool and its purpose.

## Payloads
The tool currently supports the following payloads for fuzzing:

- ** SQL Injection ** : Tests for SQLi using techniques like UNION SELECT, BLIND SQLi, and DROP TABLE.
- ** XSS (Cross-Site Scripting) ** : Sends malicious scripts using <script>, <img>, and <svg> tags.
- ** NoSQL Injection ** : Payloads crafted for NoSQL databases.
- ** OS Command Injection ** : Payloads like ping, whoami, and other command injections.
- ** Path Traversal ** : Attempts to access files like /etc/passwd.
- ** XML Injection ** : Payloads for XXE and other XML-based attacks.
