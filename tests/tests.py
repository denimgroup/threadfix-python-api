from ThreadFixProAPI import ThreadFixProAPI
from ThreadFixProAPI.Applications import ThreadFixProAPIApplications
from ThreadFixProAPI.Networks import ThreadFixProAPINetworks

import requests

def network_requests_test(threadfix, apikey):
    # Get cookie
    ret = requests.request('GET', f'{threadfix}/auth/apikey', headers={'apikey' : apikey}, verify=False)
    # Build headers
    headers = {
        "Content-Type" : "application/json",
        "API-Version" : "1.0",
        "Authorization" : "Bearer " + ret.headers['Set-Cookie']
    }
    ret = requests.request('GET', f'{threadfix}/api/network/vulnerabilities', headers=headers, verify=False)
    print(ret.status_code)

def network_test(threadfix, apikey):
    # Connect
    network_api = ThreadFixProAPINetworks(threadfix, apikey, verify_ssl=False)
    ret = network_api.VulnerabilitiesAPI.fetch_all_vulnerabilities()
    print(ret.data)

network_test('https://demo.tfint.link', 'cKj2ZmbZkZoXMML5KwAlkwHN9CQDYU38ch9fBFUYPF0')

# network_requests_test('https://demo.tfint.link', 'cKj2ZmbZkZoXMML5KwAlkwHN9CQDYU38ch9fBFUYPF0')
