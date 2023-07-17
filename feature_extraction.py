from requests import get
from string import ascii_lowercase
from bs4 import BeautifulSoup
from tldextract import extract
import ipaddress
import re
import whois
from datetime import datetime
from urllib.parse import urlparse

def get_domain(url):
    tsd, td, tsu = extract(url)
    try:
        ipaddress.ip_address(str(td))
        return td
    except:
        domain = td + '.' + tsu
        return domain
    
def contains_at(url):
    if '@' in url:
        return 1
    return 0

def contains_ip(url):
    tsd, td, tsu = extract(url)
    try:
        ipaddress.ip_address(str(td))
        return 1
    except ValueError:
        return 0

def get_length(url):
    return len(url)

def is_http(url):
    if url.startswith("http://"):
        return 1
    elif url.startswith("https://"):
        return 0
    
def uses_shortener(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
    if re.search(shortening_services,url):
        return 1
    else:
        return 0
    
def check_prefix_suffix(url):
    domain = get_domain(url)
    if "-" in url:
        return 1
    else:
        return 0

def get_domainAge(url):
    domain = get_domain(url)
    try:
        info = whois.whois(domain)
    except:
        return 0
    try:
      creation_date = info["creation_date"]
    except:
      return 0
    if creation_date == None:
      return 0
    try:
        diff = datetime.now() - creation_date
    except TypeError:
        diff = datetime.now() - creation_date[0]
    try:
        if diff.days < 365:
            return 1
        else:
            return 0
    except:
        return 1
    
def get_domainExpiry(url):
    domain = get_domain(url)
    try:
        info = whois.whois(domain)
    except:
        return 0
    try:
      expiry_date = info["expiration_date"]
    except:
      return 0
    if expiry_date == None:
      return 0
    try:
        diff = expiry_date - datetime.now()
    except TypeError:
        diff = expiry_date[0] - datetime.now()
    try:
        if diff.days < 183:
            return 1
        else:
            return 0
    except:
        return 1
    
def get_google_index(site):
    headers_Get = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    q_in = "site:"+site
    q_out = ""
    for i in range(len(q_in)):
        if q_in[i] not in ascii_lowercase:
            q = q_in[i]
            q_out += "%"+str(q.encode().hex().upper())
        else:
            q_out += q_in[i]
    url = 'https://www.google.com/search?q=' + q_out + '&ie=utf-8&oe=utf-8'
    r = get(url, headers=headers_Get)
    soup = BeautifulSoup(r.text, "html.parser")
    output = []
    for searchWrapper in soup.find_all('h3'):
        output.append(searchWrapper.text)
    if len(output)>=1:
        return 1
    else:
        return 0
    
def get_page_rank(url_in):
    domain = get_domain(url_in)
    url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    headers = {'API-OPR':'wgs04w0s0okg4wcw4g0k8w0gco4ocsckocw0okk0'}
    r = get(url, headers=headers)
    page_rank = (r.json())['response'][0]['page_rank_integer']
    try:
        if page_rank>3: #assuming 25-30% of websites are malicious
            return 1
        else:
            return 0
    except :
        return 0
    
def contains_redirect(url):
    pos = url.rfind('//')
    if pos > 7:
        return 1
    else:
        return 0
    
def contains_port(url):
    try:
        url = url.split('/')
        host = url[2]
        flag = re.search('[0-9a-fA-F.]*:[0-9]*', host)
        if flag:
            return 1
        else:
            return 0
    except:
        return 0
    
def get_depth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for i in s:
        if len(i)>0:
            depth+=1
    return depth


def extractFeatures(url):
    feature_list = []
    feature_list.append(contains_at(url))
    feature_list.append(contains_ip(url))
    feature_list.append(get_length(url))
    feature_list.append(is_http(url))
    feature_list.append(uses_shortener(url))
    feature_list.append(check_prefix_suffix(url))
    feature_list.append(get_domainAge(url))
    feature_list.append(get_domainExpiry(url))
    feature_list.append(get_google_index(url))
    feature_list.append(get_page_rank(url))
    feature_list.append(contains_redirect(url))
    feature_list.append(contains_port(url))
    feature_list.append(get_depth(url))

    return feature_list