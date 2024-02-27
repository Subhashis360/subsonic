from concurrent.futures import ThreadPoolExecutor
import re
import httpx
import datetime as dt
from fake_useragent import UserAgent
import requests

G = '\033[1;32m'
R = '\033[1;31m'

print((G+"""
  _____________ _____________  ___ ___    _____    _________ ___ ___ .___  _________
 /   _____/    |   \______   \/   |   \  /  _  \  /   _____//   |   \|   |/   _____/
 \_____  \|    |   /|    |  _/    ~    \/  /_\  \ \_____  \/    ~    \   |\_____  \ 
 /        \    |  / |    |   \    Y    /    |    \/        \    Y    /   |/        /
/_______  /______/  |______  /\___|_  /\____|__  /_______  /\___|_  /|___/_______  /
        \/                 \/       \/         \/        \/       \/             \/ 

"""))

print(f"{R}                                       SUBSONIC                         ")
print(f"{G}                               Fastest Subdomain Finder                         ")

print("\n")

domain = input(G+"[=>] Enter the Domain Name : ").lower().replace("http://", "").replace("https://", "").replace("www.", "").rstrip("/")
filename = f"{domain}.txt".strip()
output_file = f"{filename}"

yesterday = dt.date.today() - dt.timedelta(days=1)

subdomains_set = set()
unique_urls = set()

def get_subdomains(url, pattern, domain):
    try:
        with httpx.Client() as request:
            user_agent = UserAgent().random
            headers = {'User-Agent': user_agent}
            response = request.get(url, timeout=30, headers=headers)
            if response.status_code == 200:
                content = response.text
                subdomains = pattern.findall(content)
                for subdomain in subdomains:
                    if subdomain.endswith(f".{domain}"):
                        print(G+"[*] Found => "+subdomain)
                        subdomains_set.add(subdomain)
    except Exception as e:
        pass

def probe_url(url, unique_urls):
    try:
        user_agent = UserAgent().random
        headers = {'User-Agent': user_agent}
        http_url = "http://" + url
        https_url = "https://" + url

        https_response = requests.get(https_url, timeout=5, headers=headers)
        if https_response.status_code == 200:
            active_url = https_url
        elif requests.get(http_url, timeout=5, headers=headers).status_code == 200:
            active_url = http_url
        else:
            return
        print(G+f"[*] Active Found => {active_url}")
        unique_urls.add(active_url)

        with open(output_file, "a") as file:
            file.write(f"{active_url}\n")
    except httpx.RequestError:
        pass

def process_source(source):
    source_url, source_pattern = source
    with ThreadPoolExecutor(25) as executor:
        executor.submit(get_subdomains, source_url.format(domain=domain), source_pattern, domain)

sources = [
    ("https://www.abuseipdb.com/whois/{domain}", re.compile(r'<li>\w.*</li>')),
    ("https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/passive_dns", re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")),
    ("https://api.subdomain.center/?domain={domain}", re.compile(r"")),
    ("https://columbus.elmasy.com/api/lookup/{domain}?days=-1", re.compile(r"")),
    ("https://jonlu.ca/anubis/subdomains/{domain}", re.compile(r"")),
    ("https://dnsrepo.noc.org/?domain={domain}", re.compile(rf"\b[a-zA-Z0-9]+\b\.{domain}\b")),
    ("https://api.hackertarget.com/hostsearch/?q={domain}", re.compile(r"")),
    ("https://rapiddns.io/subdomain/{domain}?full=1", re.compile(rf"\b[a-zA-Z0-9]+\b\.{domain}\b")),
    ("https://urlscan.io/api/v1/search/?q=page.domain:{domain}&size=10000", re.compile(r"")),
    ("http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey", re.compile(r"https://([\w-]+\.{domain})")),
    ("https://seckrd.com/subdomain-finder.php", re.compile(rf"https://([\w-]+\.{domain})")),
    ("https://crt.sh/?q=%25.{domain}", re.compile(rf"\b[a-zA-Z0-9.*-]+\.{re.escape(domain)}\b")),
    ("https://shrewdeye.app/domains/{domain}.txt", re.compile(rf"\b[a-zA-Z0-9]+\b\.{domain}\b")),
    ("https://subdomainfinder.c99.nl/scans/{yesterday}/{domain}", re.compile(rf"https?://([\w-]+\.{domain})")),
    ("https://www.google.com/search?q=site%3A{domain}", re.compile(r'(https?://(?:[\w-]+\.)+[\w-]+(?:\/\w*)*)')),
    ("https://crt.sh/?q=%25.{domain}", re.compile(r'>((?:[\w-]+\.)+[\w-]+)</TD>')),
    ("https://www.bing.com/search?q=site%3A{domain}", re.compile(r'(https?://(?:[\w-]+\.)+[\w-]+(?:\/\w*)*)')),
    ("https://www.baidu.com/s?wd=site%3A{domain}", re.compile(r'(https?://(?:[\w-]+\.)+[\w-]+(?:\/\w*)*)')),
    ("https://search.yahoo.com/search?p=site%3A{domain}", re.compile(r'(https?://(?:[\w-]+\.)+[\w-]+(?:\/\w*)*)')),
    ("https://searchdns.netcraft.com/?restriction=site+contains&host=.{domain}", re.compile(r'(\w+\.{domain})')),
    ("https://www.ask.com/web?page=2&q=site:{domain}", re.compile(r'(https?://(?:[\w-]+\.)+[\w-]+(?:\/\w*)*)')),
]


with ThreadPoolExecutor(15) as executor:
    executor.map(process_source, sources)


with open(f"{domain}.txt", "w") as file:
    if subdomains_set:
        for subdomain in subdomains_set:
            file.write(subdomain + "\n")
    else:
        print(R+f"[=>] No Subdomains Found for this [[{domain}]]")
        print(G+"[=>] Thanks For using Subsonic")
        exit()

print(G+f"[=>] Subdomains for {domain} have been saved in [[{domain}.txt]] Total Found => [{len(subdomains_set)}]")

probe_input = input(R+f"[=>] Do you want to Fetch Working Subdomains From this {domain} ? (yes/no): ").lower().strip()

if probe_input.startswith("y"):
    with open(filename, "r") as file:
        urls = file.read().splitlines()

    with ThreadPoolExecutor(55) as executor:
        executor.map(lambda url: probe_url(url, unique_urls), urls)
        
    if unique_urls:
        with open(output_file, "w") as file:
            file.write("\n".join(unique_urls))
        print(R+f"[=>] Active Results of [{len(unique_urls)}] have been saved in [[{output_file}]]")
        print(G+"[=>] Thanks For using Subsonic")
    else:
        print(R+f"[=>] No active Subdomain Found")
        print(G+"[=>] Thanks For using Subsonic")
else:
    print(G+"[=>] Thanks For using Subsonic")
