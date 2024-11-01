import math
import string
import socket
import os
import ipaddress
import Levenshtein
import traceback
from ail_typo_squatting import runAll
import math
from tqdm import tqdm
from urllib.parse import urlparse
import requests
import csv
from ssl_checker import SSLChecker
import whois
from datetime import datetime
from bs4 import BeautifulSoup
from Known_Sites import TEMPORARY_DOMAIN_PLATFORMS
import firebase_admin
from firebase_admin import firestore
from firebase_admin import credentials

PRIVATE_KEY_PATH = "firebase/phishr-d74a9-firebase-adminsdk-vcpiv-0328924687.json"
cred = credentials.Certificate(PRIVATE_KEY_PATH)
firebase_admin.initialize_app(cred)
db = firestore.client()

def is_https(url):
    return url.startswith('https')

def check_top1million_database(url):
    with open('top-1million-sites.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if url in row[1] or url in "https://www."+row[1]:
                print(f"{url} is in the top 1 million websites according to Alexa.")
                return True
        print(f"{url} is not in the top 1 million websites according to Alexa.")
        return False

def check_top1million_database_2(url):
    domain = urlparse(url).netloc
    if not domain:
        domain = url.split('/')[0]
    with open('top-1million-sites.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if domain == row[1] or domain == "www."+row[1]:
                print(f"{domain} is in the top 1 million websites according to Alexa.")
                return True
        print(f"{domain} is not in the top 1 million websites according to Alexa.")
        return False

def check_ssl_certificate(url):
    try:
        ssl_checker = SSLChecker()
        args = {'hosts': [url]}
        output = ssl_checker.show_result(ssl_checker.get_args(json_args=args))
        if "cert_valid" in output:
            return True
        else:
            return False
    except:
        return False

def is_temporary_domain(url):
    for temp_domain in TEMPORARY_DOMAIN_PLATFORMS:
        if temp_domain in url:
            return True
    return False

def get_registrar(url):
    try:
        w = whois.whois(url)
        registrar = w.registrar
        return registrar
    except Exception as e:
        print(f"Error: {e}")
        return None

def get_days_since_creation(domain, months):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if type(creation_date) == list:
            creation_date = creation_date[0]
        days_since_creation = (datetime.now() - creation_date).days
        months_since_creation = days_since_creation / 30
        return months_since_creation >= months
    except Exception as e:
        print("Unable to access Registeration date for Domain !")
        return None

def check_mcafee_database(url):
    mcafee_url = f"https://www.siteadvisor.com/sitereport.html?url={url}"
    response = requests.get(mcafee_url)

    if response.status_code == 200:
        if "is safe" in response.text:
            print(f"{url} is safe to visit according to McAfee SiteAdvisor.")
            return True
        else:
            print(f"{url} may be dangerous according to McAfee SiteAdvisor. Please proceed with caution.")
            return False
    else:
        print("Unable to check URL against McAfee SiteAdvisor database.")
        return False

def check_google_safe_browsing(url):
    google_url = f"https://transparencyreport.google.com/safe-browsing/search?url={url}"
    response = requests.get(google_url)

    if response.status_code == 200:
        if "No unsafe content found" in response.text:
            print(f"{url} is safe to visit according to Google Safe Browsing.")
            return True
        else:
            print(f"{url} may be dangerous according to Google Safe Browsing. Please proceed with caution.")
            return False
    else:
        print("Unable to check URL against Google Safe Browsing database.")
        return False

def checkLocalBlacklist(url):
    dataset = "blacklisted_sites.txt"
    with open(dataset, 'r') as file:
        for line in file:
            website = line.strip()
            if url == website:
                return True
    return False

def is_valid_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False

def check_ip_in_ipsets(ip):
    ip_address = ipaddress.ip_address(ip)
    ipset_directory = "blocklist-ipsets/IpSets"

    for root, dirs, files in os.walk(ipset_directory):
        for file in tqdm(files, desc="Checking IPset files"):
            ipset_file = os.path.join(root, file)
            with open(ipset_file, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            subnet = ipaddress.ip_network(line)
                            if ip_address in subnet:
                                return True
                        except ValueError:
                            pass
    return False

def checkSucuriBlacklists(url):
    check_url = f"https://sitecheck.sucuri.net/results/{url}"
    response = requests.get(check_url)

    if "Site is Blacklisted" in response.text:
        print(f"{url} is NOT safe to visit according to Sucuri Blacklists.")
        return False
    else:
        print(f"{url} is safe to visit according to Sucuri Blacklists.")
        return True

def checkURLVoid(url):
    try:
        scan_url = f"https://www.urlvoid.com/scan/{url}"
        response = requests.get(scan_url)
        soup = BeautifulSoup(response.content, 'html.parser')
        span_tag = soup.find('span', class_="label label-danger")
        if span_tag:
            label_text = span_tag.get_text().strip()
            return int(label_text.split('/')[0])
        else:
            return 0
    except:
        return 0

def check_Nortan_WebSafe(url):
    try:
        response = requests.get(f"https://safeweb.norton.com/report/show?url={url}")
        html_content = response.text
        if "known dangerous webpage" in html_content:
            print("The URL is NOT safe as per Nortan Safe Web !")
            return False
        else:
            print("The URL is safe as per Nortan Safe Web !")
            return True
    except Exception:
        return True

def get_domain_length(url):
    return len(url)

def get_domain_entropy(url):
    domain = urlparse(url).netloc
    alphabet = string.ascii_lowercase + string.digits
    freq = [0] * len(alphabet)
    for char in domain:
        if char in alphabet:
            freq[alphabet.index(char)] += 1
    entropy = 0
    for count in freq:
        if count > 0:
            freq_ratio = float(count) / len(domain)
            entropy -= freq_ratio * math.log(freq_ratio, 2)
    return round(entropy, 2)

def is_ip_address(url):
    domain = urlparse(url).netloc
    try:
        socket.inet_aton(domain)
        return 1
    except socket.error:
        return 0

def has_malicious_extension(url):
    _, ext = os.path.splitext(url)
    malicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.scr', '.js', '.vbs',
                            '.hta', '.ps1', '.jar', '.py', '.rb']

    if ext.lower() in malicious_extensions:
        return 1
    else:
        return 0

def query_params_count(url):
    parsed = urlparse(url)
    query_params = parsed.query.split('&')
    if query_params[0] == '':
        return 0
    else:
        return len(query_params)

def path_tokens_count(url):
    parsed = urlparse(url)
    path_tokens = parsed.path.split('/')
    path_tokens = [token for token in path_tokens if token]
    return len(path_tokens)

def hyphens_count(url):
    parsed = urlparse(url)
    return url.count('-')

def digits_count(url):
    return sum(c.isdigit() for c in url)

def has_special_characters(url):
    special_chars = ['@', '!', '#', '$', '%', '^', '&', '*', '_', '+']
    for char in special_chars:
        if char in url:
            return 1
    return 0

def getInputArray(url):
    result = []
    result.append(get_domain_length(url))
    result.append(get_domain_entropy(url))
    result.append(is_ip_address(url))
    result.append(has_malicious_extension(url))
    result.append(query_params_count(url))
    result.append(path_tokens_count(url))
    result.append(hyphens_count(url))
    result.append(digits_count(url))
    result.append(has_special_characters(url))
    return result

def isURLMalicious(url, clf):
    input = getInputArray(url)
    prediction = clf.predict([input])[0]
    return prediction

def calculate_url_similarity(url1, url2):
    levenshtein_distance = Levenshtein.distance(url1, url2)
    similarity_score = (1 - levenshtein_distance / max(len(url1), len(url2))) * 10
    return similarity_score

def strip_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if not domain:
        domain = parsed_url.path.strip("/")
    if not domain.startswith("www."):
        domain = domain.lstrip("www.")
    return domain

def generate_similar_urls(url, max_urls=5000):
    resultList = list()
    pathOutput = "./type-squating-data/"
    formatoutput = "text"

    resultList = runAll(
        domain=url,
        limit=math.inf,
        pathOutput=pathOutput,
        formatoutput=formatoutput,
        verbose=False,
        givevariations=False,
        keeporiginal=False
    )

    similar_urls = []
    if resultList is not None:
        for modifiedUrl in resultList:
            if calculate_url_similarity(url, modifiedUrl) > 5:
                similar_urls.append(modifiedUrl)

            if len(similar_urls) >= max_urls:
                return similar_urls
    return similar_urls

def find_target_urls(fake_url, similarity_score=7):
    fake_url = str(fake_url).lower()
    similar_urls = []
    domain = urlparse(fake_url).netloc
    if not domain:
        domain = fake_url.split('/')[0]
    with open('top-1million-sites.csv', 'r') as f:
        reader = csv.reader(f)
        print("Finding target URL...")
        for row in reader:
            if calculate_url_similarity(domain, row[1]) > similarity_score:
                similar_urls.append(row[1])
        return similar_urls

def convert_datetime_list_to_string(date_list):
    formatted_strings = []
    for dt in date_list:
        if isinstance(dt, datetime):
            formatted_string = "{:%d %B %Y, %H:%M:%S}".format(dt)
            formatted_strings.append(formatted_string)
        else:
            formatted_strings.append(str(dt))
    return formatted_strings

def array2String(someList):
    output = ""
    for i in someList:
        output = output + str(i) + " , "
    return output

def check_domain_registration(domain):
    domain = strip_url(domain)
    try:
        w = whois.whois(domain)
        if w.status:
            return w
        else:
            return None
    except Exception as e:
        print("Error occcured in check_domain_registration() !")
        print("ERROR : ",str(e))
        traceback.print_exc()
        return None

def process_domain_details(registered_urls):
    AlldomainDetails = []

    for domainDetails in registered_urls:
        registrar = domainDetails["registrar"]

        domain_name = domainDetails["domain_name"]
        if isinstance(domain_name, list):
            domain_name = domain_name[0]

        country = domainDetails["country"]
        if isinstance(country, list):
            country = array2String(country)
        domainDetails["country"] = country

        creation_date = domainDetails["creation_date"]
        if isinstance(creation_date, list):
            creation_date = convert_datetime_list_to_string(creation_date)
            creation_date = creation_date[0]
        else:
            creation_date = "{:%d %B %Y, %H:%M:%S}".format(creation_date)
        domainDetails["creation_date"] = creation_date

        name_servers = domainDetails["name_servers"]
        if isinstance(name_servers, list):
            name_servers = array2String(name_servers)
        domainDetails["name_servers"] = name_servers

        output = {
            "registrar": registrar,
            "domain_name": str(domain_name).upper(),
            "country": country,
            "creation_date": creation_date,
            "name_servers": name_servers,
            "status": "VERIFIED ✅"
        }

        AlldomainDetails.append(output)

    return AlldomainDetails

def process_unregistered_urls(unregistered_urls):
    urls = []

    for url in unregistered_urls:
        if len(urls) >= 500:
            break

        output = {
            "registrar": None,
            "domain_name": url,
            "country":  None,
            "creation_date":  None,
            "name_servers":  None,
            "status":  "UNVERIFIED ✖️",
        }

        output["domain_name"] = str(url).upper()
        urls.append(output)

    return urls

def registered_similar_domains(domain, max_urls=20):
    if check_domain_registration(domain) == None:
        if check_top1million_database(domain) or check_top1million_database_2(domain):
            print("Domain in Top 1 Million Sites !")
        else:
            return False

    output = {
        "unregistered_urls": None,
        "registered_urls": None,
        "total_permutations": None,
    }

    domain = strip_url(domain)
    original_domain = domain
    print("Stripped Domain : ", domain)

    similar_urls = generate_similar_urls(domain)
    output["total_permutations"] = len(similar_urls)
    print("Total Similar URLs : ", len(similar_urls))

    urls = []
    stopper = 0
    for domain in similar_urls:
        if domain==original_domain:
            continue

        if stopper >= 20:
            print("No registered domain found for 20 iterations ! Stopping Loop. ")
            break

        if len(urls) >= max_urls:
            output["unregistered_urls"] = similar_urls
            output["registered_urls"] = urls
            return output

        registration_details = check_domain_registration(domain)
        if registration_details:
            print(f"The domain '{domain}' is active and registered.")
            stopper = 0
            urls.append(registration_details)
        else:
            stopper = stopper + 1
            similar_urls = [x for x in similar_urls if x != domain]
            print(f"The domain '{domain}' is not registered or inactive.")

    output["unregistered_urls"] = similar_urls
    output["registered_urls"] = urls
    return output

def getTypoSquattedDomains(domain,max_num=20):
    output = registered_similar_domains(domain, max_num)

    if output==False:
        return False

    total_permutations = output["total_permutations"]
    registered_urls = output["registered_urls"]
    unregistered_urls = output["unregistered_urls"]

    registered_urls = process_domain_details(registered_urls)
    unregistered_urls = process_unregistered_urls(unregistered_urls)
    allDomains = registered_urls + unregistered_urls

    result = {
        "total_permutations": total_permutations,
        "allDomains": allDomains
    }

    return result

def url_in_reporting_database(url):
    reported_urls_query = db.collection('Reported_Urls').where("Url", "==", url)
    reported_urls_docs = reported_urls_query.stream()

    bulk_reported_urls_query = db.collection('Bulk_Reported_Urls').where("Url", "==", url)
    bulk_reported_urls_docs = bulk_reported_urls_query.stream()

    if len(list(reported_urls_docs)) > 0:
        return True

    if len(list(bulk_reported_urls_docs)) > 0:
        return True

    return False