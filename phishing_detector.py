# URL Phishing Detector
# Author: Ryan Feneley
# August 2024

import re
import requests

# Heuristic rules for detecting phishing URLs
def is_phishing(url):
    # Rule 1: Too many subdomains
    subdomain_count = url.count('.')
    if subdomain_count > 3:
        return True

    # Rule 2: Presence of IP address in the URL
    if re.match(r'http://\d+\.\d+\.\d+\.\d+', url):
        return True

    # Rule 3: Homograph attack detection (e.g., using similar-looking characters)
    homograph_regex = r'[a-zA-Z0-9]*[а-яА-ЯёЁ][a-zA-Z0-9]*'  # Cyrillic characters mixed
    if re.search(homograph_regex, url):
        return True

    # Rule 4: Length of the URL
    if len(url) > 75:
        return True

    # Rule 5: Use of suspicious keywords
    suspicious_keywords = ['login', 'secure', 'account', 'verify', 'update', 'suspend']
    if any(keyword in url for keyword in suspicious_keywords):
        return True

    return False

# Check the URL with VirusTotal API for additional checks
def check_with_virustotal(url, api_key):
    vt_url = "https://www.virustotal.com/api/v3/urls"
    encoded_url = requests.utils.quote(url)
    headers = {
        "x-apikey": api_key
    }

    response = requests.post(f"{vt_url}", headers=headers, data={"url": encoded_url})
    if response.status_code == 200:
        result = response.json()
        if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            return True
    return False

if __name__ == "__main__":
    # Accept URL input from the user
    url = input("Enter the URL to check for phishing: ")

    # Check if the URL is likely to be phishing
    if is_phishing(url):
        print("The URL is likely to be a phishing attempt based on heuristic rules.")
    else:
        print("The URL appears to be safe based on heuristic rules.")

    # Optional: Check with VirusTotal
    use_vt = input("Would you like to check with VirusTotal? (y/n): ").strip().lower()
    if use_vt == 'y':
        api_key = input("Enter your VirusTotal API key: ")
        if check_with_virustotal(url, api_key):
            print("The URL is flagged as malicious by VirusTotal.")
        else:
            print("VirusTotal analysis did not flag the URL as malicious.")
