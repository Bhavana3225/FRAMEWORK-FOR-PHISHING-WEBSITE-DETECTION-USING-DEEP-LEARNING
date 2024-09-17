import pandas as pd
from urllib.parse import urlparse, urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests

# Datasets Used
# 1. Source http://data.phishtank.com/data/online-valid.csv
data0 = pd.read_csv("Datasets/online-valid.csv")
data0.head()
data0.shape

# Collecting 5,000 Phishing URLs randomly
phishurl = data0.sample(n=5000, random_state=12).copy()
phishurl = phishurl.reset_index(drop=True)
phishurl.head()
phishurl.shape

# Datasets Used
# 2. Source kaggle/input/phishing-detection/1.Benignlistbigfinal.csv
# Loading legitimate files
data1 = pd.read_csv("Datasets/Benignlistbigfinal.csv")
data1.columns = ['URLs']
data1.head()

# Collecting 5,000 Legitimate URLs randomly
legiurl = data1.sample(n=5000, random_state=12).copy()
legiurl = legiurl.reset_index(drop=True)
legiurl.head()
legiurl.shape

# 1. Domain of the URL (Domain)
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

# 2. Checks for IP address in URL (Have IP)
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip

# 3. Checks the presence of @ in URL (Have At)
def haveAtSign(url):
    if "@" in url:
        at = 1
    else:
        at = 0
    return at

# 4. Finding the length of URL and categorizing (URL Length)
def getLength(url):
    if len(url) < 54:
        length = 0
    else:
        length = 1
    return length

# 5. Gives the number of '/' in URL (URL Depth)
def getDepth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth += 1
    return depth

# 6. Checking for redirection '//' in the URL (Redirection)
def redirection(url):
    pos = url.find('//')
    if pos > 6:
        if pos > 7:
            return 1
        else:
            return 0
    else:
        return 0

# 7. Existence of HTTPS Token in the Domain Part of the URL (https Domain)
def httpDomain(url):
    domain = urlparse(url).netloc
    if 'https' in domain:
        return 1
    else:
        return 0

# 8. Checking for Shortening Services in URL (Tiny URL)
def tinyURL(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|" \
                          r"is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|" \
                          r"su\.pr|twurl\.nl|snipurl\.com|sn\.im|short\.to|BudURL\.com|ping\.fm|" \
                          r"post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|" \
                          r"short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|bit\.do|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|" \
                          r"ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|" \
                          r"cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|" \
                          r"vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net"
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0

# 9. Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1  # phishing
    else:
        return 0  # legitimate

# 10. Web traffic (Web Traffic)
def webTraffic(url):
    rank = 0
    api = '9933f02e3eb544e78e9a3e6b4a7f07b0'
    myurl = f'https://api.similarweb.com/v1/similar-rank/{url}/rank?apikey={api}'
    response = requests.get(myurl)
    if response.status_code == 200:
        try:
            data = response.json()
            rank = int(data["similar_rank"]["rank"])
        except JSONDecodeError as e:
            error = f'Error: Could not parse response JSON. Details: {str(e)}'
    else:
        error = 'Error: Could not retrieve ranking data.'
    if rank < 100000:
        return 1
    else:
        return 0

# 11. Survival time of the domain: The difference between termination time and creation time (Domain Age)
def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
        except:
            return 1
    if ((expiration_date is None) or (creation_date is None)):
        return 1
    elif ((type(expiration_date) is list) or (type(creation_date) is list)):
        return 1
    else:
        ageofdomain = abs((expiration_date - creation_date).days)
        if ((ageofdomain / 30) < 6):
            age = 1
        else:
            age = 0
    return age
