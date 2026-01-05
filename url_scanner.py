# Input the URL
url = input("Enter the URL: ")
print("Url:", url)


# Cleaning the URL
def cleaning_url(clean_url):
    clean_url = clean_url.replace(" ", "")
    clean_url = clean_url.lower()
    if "http://" not in clean_url and "https://" not in clean_url:
        clean_url = "http://" + clean_url
    return clean_url


risk_counter = 0

# Connecting clean function with User Input
cleaned_url = cleaning_url(url)


# Url Length Checker
cleaned_url_length = len(cleaned_url)
if cleaned_url_length > 150:
    print("This URL is unusually long. Long URLs are sometimes used to obscure malicious content, but length alone does not indicate a threat. Further analysis is recommended.")
    risk_counter += 1


# Separate the domain name first
domain_url = cleaned_url.replace("https://", "").replace("http://", "")
domain = domain_url.split("/")[0]


# Hyphen Counter
hyphen_count = domain.count("-")
if hyphen_count >= 2:
    print("Multiple hyphens detected in the domain. This pattern is commonly observed in phishing URLs and increases the risk score.")
    risk_counter += 1


# IP address Detection
def ipaddress(domain):
    parts = domain.split(".")
    if len(parts) != 4:
        return False
    for partnum in parts:
        if not partnum.isdigit():
            return False

        number = int(partnum)
        if number < 0 or number > 255:
            return False
    return True


is_ipaddress = ipaddress(domain)

if is_ipaddress is True:
    print("This URL uses a raw IP address instead of a domain name. URLs that rely on IP addresses are commonly associated with phishing or malicious activity, especially when used to bypass domain-based trust.")
    risk_counter += 2


# Suspicious Keyword Detection
wordlist = ["login", "verify", "secure", "update",
            "account", "confirm", "reset", "payment", "support"]
counter = 0
for words in wordlist:
    if words in cleaned_url:
        counter += 1
if counter >= 1:
    print("Suspicious keywords detected in the URL. Phishing links often use urgency or trust related terms such as login, verify, or update to manipulate users.")
    risk_counter += 1


# Risk Counter
print("\nFinal Risk Score:", risk_counter)

if risk_counter == 0:
    print("Risk Level: Low. No common phishing indicators detected.")
elif risk_counter <= 2:
    print("Risk Level: Medium. Some suspicious patterns detected. Caution advised.")
else:
    print("Risk Level: High. Multiple phishing indicators detected. Avoid interacting with this URL.")
