import argparse
import requests
import socket
import ssl
from http.cookies import SimpleCookie

def display_ascii_art():
    ascii_art = """
 __   __  _______  _______  _______  __    _ 
|  | |  ||       ||       ||   _   ||  |  | |
|  |_|  ||  _____||       ||  |_|  ||   |_| |
|       || |_____ |       ||       ||       |
|       ||_____  ||      _||       ||  _    |
 |     |  _____| ||     |_ |   _   || | |   |
  |___|  |_______||_______||__| |__||_|  |__|

    """
    print(ascii_art)

def check_vulnerabilities(url, silent, checkall, ports, ssl_check, cookies, content, proxy, timeout, redirects):
    print(f"Checking vulnerabilities for: {url}")
    print("-" * 50)
    # Checking response headers
    if checkall:
        response = requests.head(url, proxies={"http": proxy, "https": proxy}, timeout=timeout)
        print("Response Headers:")
        print(response.headers)
        print("-" * 50)

    # Checking open ports
    if ports:
        print("Open Ports:")
        open_ports = get_open_ports(url)
        if open_ports:
            for port in open_ports:
                print(f"Port {port} open")
        else:
            print("No open ports found.")
        print("-" * 50)

    # Checking SSL/TLS vulnerabilities
    if ssl_check:
        print("Checking SSL/TLS vulnerabilities:")
        ssl_results = check_ssl_vulnerabilities(url)
        print(ssl_results)
        print("-" * 50)

    # Checking cookies
    if cookies:
        print("Checking cookies:")
        cookie_results = check_cookies(url)
        print(cookie_results)
        print("-" * 50)

    # Checking page content
    if content:
        print("Checking page content:")
        page_content = get_page_content(url)
        if page_content:
            print(page_content)
        else:
            print("No content found.")
        print("-" * 50)

    # Checking redirects
    if redirects:
        print("Checking redirects:")
        redirections = get_redirects(url)
        if redirections:
            for redirect in redirections:
                print(f"Redirect: {redirect}")
        else:
            print("No redirects found.")
        print("-" * 50)

def get_open_ports(url):
    try:
        ip = socket.gethostbyname(url)
        open_ports = []
        for port in range(1, 65536):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports
    except socket.gaierror:
        return []

def check_ssl_vulnerabilities(url):
    try:
        context = ssl.create_default_context()
        ssl_socket = context.wrap_socket(socket.socket(), server_hostname=url)
        ssl_socket.connect((url, 443))
        ssl_info = ssl_socket.getpeercert()
        ssl_socket.close()
        return ssl_info
    except ssl.SSLError:
        return "An SSL error occurred."

def check_cookies(url):
    try:
        response = requests.get(url)
        cookies = response.headers.get("Set-Cookie")
        if cookies:
            cookie = SimpleCookie()
            cookie.load(cookies)
            return cookie
        else:
            return "No cookies found."
    except requests.exceptions.RequestException:
        return "An error occurred while checking cookies."

def get_page_content(url):
    try:
        response = requests.get(url)
        return response.text
    except requests.exceptions.RequestException:
        return None

def get_redirects(url):
    try:
        response = requests.get(url)
        return response.history
    except requests.exceptions.RequestException:
        return []

def main():
    parser = argparse.ArgumentParser(description="Check vulnerabilities of a website")
    parser.add_argument("-u", "--url", required=True, help="URL of the website to check")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent execution")
    parser.add_argument("-c", "--checkall", action="store_true", help="Perform complete check")
    parser.add_argument("--ports", action="store_true", help="Display open ports")
    parser.add_argument("--ssl", action="store_true", help="Check SSL/TLS vulnerabilities")
    parser.add_argument("--cookies", action="store_true", help="Check cookies")
    parser.add_argument("--content", action="store_true", help="Check page content")
    parser.add_argument("--proxy", help="Proxy address (e.g., http://proxy.example.com:8080)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in seconds (default: 10)")
    parser.add_argument("--redirects", action="store_true", help="Check redirects")

    args = parser.parse_args()

    if not args.silent:
        display_ascii_art()

    check_vulnerabilities(args.url, args.silent, args.checkall, args.ports, args.ssl, args.cookies, args.content,
                          args.proxy, args.timeout, args.redirects)

if __name__ == "__main__":
    main()
