import argparse
import requests
import socket
import ssl
from http.cookies import SimpleCookie

def display_ascii_art():
    ascii_art = """
 _____ _           _   _            _   _____           _             
|  __ (_)         | | (_)          | | |_   _|         | |            
| |__) | _ __   __| |  _  ___  ___ | |_  | |  _ __  ___| |_ ___  _ __ 
|  ___/ | '_ \ / _` | | |/ _ \/ __|| __| | | | '_ \/ __| __/ _ \| '__|
| |   | | | | | (_| | | |  __/\__ \| |_ _| |_| | | \__ \ || (_) | |   
|_|   |_|_| |_|\__,_| |_|\___||___/ \__|_____|_| |_|___/\__\___/|_|   
    """
    print(ascii_art)

def check_vulnerabilities(url, silent, checkall, ports, ssl_check, cookies, content, proxy, timeout, redirects):
    print(f"Vérification des vulnérabilités pour : {url}")
    print("-" * 50)
    # Vérification des en-têtes de réponse
    if checkall:
        response = requests.head(url, proxies={"http": proxy, "https": proxy}, timeout=timeout)
        print("En-têtes de réponse :")
        print(response.headers)
        print("-" * 50)

    # Vérification des ports ouverts
    if ports:
        print("Ports ouverts :")
        open_ports = get_open_ports(url)
        if open_ports:
            for port in open_ports:
                print(f"Port {port} ouvert")
        else:
            print("Aucun port ouvert trouvé.")
        print("-" * 50)

    # Vérification des vulnérabilités SSL/TLS
    if ssl_check:
        print("Vérification des vulnérabilités SSL/TLS :")
        ssl_results = check_ssl_vulnerabilities(url)
        print(ssl_results)
        print("-" * 50)

    # Vérification des cookies
    if cookies:
        print("Vérification des cookies :")
        cookie_results = check_cookies(url)
        print(cookie_results)
        print("-" * 50)

    # Vérification du contenu de la page
    if content:
        print("Vérification du contenu de la page :")
        page_content = get_page_content(url)
        if page_content:
            print(page_content)
        else:
            print("Aucun contenu trouvé.")
        print("-" * 50)

    # Vérification des redirections
    if redirects:
        print("Vérification des redirections :")
        redirections = get_redirects(url)
        if redirections:
            for redirect in redirections:
                print(f"Redirection : {redirect}")
        else:
            print("Aucune redirection trouvée.")
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
        return "Une erreur SSL s'est produite."

def check_cookies(url):
    try:
        response = requests.get(url)
        cookies = response.headers.get("Set-Cookie")
        if cookies:
            cookie = SimpleCookie()
            cookie.load(cookies)
            return cookie
        else:
            return "Aucun cookie trouvé."
    except requests.exceptions.RequestException:
        return "Une erreur s'est produite lors de la vérification des cookies."

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
    parser = argparse.ArgumentParser(description="Vérification des vulnérabilités d'un site")
    parser.add_argument("-u", "--url", required=True, help="URL du site à vérifier")
    parser.add_argument("-s", "--silent", action="store_true", help="Exécution silencieuse")
    parser.add_argument("-c", "--checkall", action="store_true", help="Vérification complète")
    parser.add_argument("--ports", action="store_true", help="Afficher les ports ouverts")
    parser.add_argument("--ssl", action="store_true", help="Vérifier les vulnérabilités SSL/TLS")
    parser.add_argument("--cookies", action="store_true", help="Vérifier les cookies")
    parser.add_argument("--content", action="store_true", help="Vérifier le contenu de la page")
    parser.add_argument("--proxy", help="Adresse du proxy (ex: http://proxy.example.com:8080)")
    parser.add_argument("--timeout", type=int, default=10, help="Délai d'attente en secondes (par défaut: 10)")
    parser.add_argument("--redirects", action="store_true", help="Vérifier les redirections")

    args = parser.parse_args()

    if not args.silent:
        display_ascii_art()

    check_vulnerabilities(args.url, args.silent, args.checkall, args.ports, args.ssl, args.cookies, args.content,
                          args.proxy, args.timeout, args.redirects)

if __name__ == "__main__":
    main()
