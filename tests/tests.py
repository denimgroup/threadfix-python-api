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
    ret = requests.request('GET', f'{threadfix}/api/network/vulnerabilities?_sort=ipAddress&ipAddress:in=64.41.0.0', headers=headers, verify=False)
    print(ret.json())

def network_test(threadfix, apikey):
    # Connect
    network_api = ThreadFixProAPINetworks(threadfix, apikey, verify_ssl=False)
    ret = network_api.VulnerabilitiesAPI.fetch_all_vulnerabilities()
    print(ret.success)
    ret2 = network_api.VulnerabilitiesAPI.fetch_all_vulnerabilities(href=ret.data['_links']['next']['href'])
    print(ret2.data)

def network_requests_test_asset_vulns(threadfix, apikey):
    # Get cookie
    ret = requests.request('GET', f'{threadfix}/auth/apikey', headers={'apikey' : apikey}, verify=False)
    # Build headers
    headers = {
        "Content-Type" : "application/json",
        "API-Version" : "1.0",
        "Authorization" : "Bearer " + ret.headers['Set-Cookie']
    }
    ret = requests.request('GET', f'{threadfix}/api/network/vulnerabilities?_sort=ipAddress&ipAddress:in=64.41.0.0', headers=headers, verify=False)
    print(ret.json())

def network_test_asset_vulns(threadfix, apikey):
    # Connect
    network_api = ThreadFixProAPINetworks(threadfix, apikey, verify_ssl=False)
    ret = network_api.SearchAPI.get_asset_vulnerability_details('20d52162-9060-41c3-b2f4-9ccb39df3ecd')
    print(ret.data)

# network_test('https://demo.tfint.link', 'cKj2ZmbZkZoXMML5KwAlkwHN9CQDYU38ch9fBFUYPF0')

# network_requests_test('https://demo.tfint.link', 'cKj2ZmbZkZoXMML5KwAlkwHN9CQDYU38ch9fBFUYPF0')

# network_requests_test_asset_vulns('https://demo.tfint.link', 'cKj2ZmbZkZoXMML5KwAlkwHN9CQDYU38ch9fBFUYPF0')

network_test_asset_vulns('https://demo.tfint.link', 'cKj2ZmbZkZoXMML5KwAlkwHN9CQDYU38ch9fBFUYPF0')
