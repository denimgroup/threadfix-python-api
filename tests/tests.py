from ThreadFixProAPI import ThreadFixProAPI
from ThreadFixProAPI.Applications import ThreadFixProAPIApplications
from ThreadFixProAPI.Networks import ThreadFixProAPINetworks

import requests
import math

def network_requests_test(threadfix, apikey):
    # Get cookie
    ret = requests.request('GET', f'{threadfix}/auth/apikey', headers={'apikey' : apikey}, verify=False)
    # Build headers
    headers = {
        "Content-Type" : "application/json",
        "API-Version" : "1.0",
        "Authorization" : "Bearer " + ret.headers['Set-Cookie']
    }
    ret = requests.request('GET', f'{threadfix}/api/network/vulnerabilities?ipAddress:in=64.41.0.0/16', headers=headers, verify=False)
    print(ret.json())

def network_test(threadfix, apikey):
    # Connect
    network_api = ThreadFixProAPINetworks(threadfix, apikey, verify_ssl=False)
    ret = network_api.VulnerabilitiesAPI.fetch_all_vulnerabilities()
    print(ret.success)
    ret2 = network_api.VulnerabilitiesAPI.fetch_all_vulnerabilities(href=ret.data['_links']['next']['href'])
    print(ret2.data['resources'][0])

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
    vulns = []
    ret = network_api.SearchAPI.get_asset_vulnerability_details('e7280910-82f1-4fbc-b939-1802e1e8e4c0')
    for page in range(math.ceil(ret.data['totalCount'] / ret.data['count'])):
        data = network_api.SearchAPI.get_asset_vulnerability_details('e7280910-82f1-4fbc-b939-1802e1e8e4c0', page=page+1)
        vulns.extend(data.data['content'])
    print(vulns[0])

def network_test_bulk_update_status(threadfix, apikey):
    tf_api = ThreadFixProAPI(threadfix, apikey, verify_ssl=False)
    vulns = ['23cb56e8-02b5-4f53-838f-34af182edcab']
    ret = tf_api.Networks.BatchAPI.bulk_update_vulnerability_status('OPEN', vulns)
    print(ret.data)

def get_vuln_by_id_test(threadfix, apikey):
    tf_api = ThreadFixProAPI(threadfix, apikey, verify_ssl=False)
    vuln_id = 'c87081ca-77da-4e94-b0d3-a05c5f1e6095'
    ret = tf_api.Networks.VulnerabilitiesAPI.find_vulnerability_by_id(vuln_id)
    print(ret.data)

# network_test('https://demo.tfint.link', 'cKj2ZmbZkZoXMML5KwAlkwHN9CQDYU38ch9fBFUYPF0')

# network_requests_test('https://demo.tfint.link', 'cKj2ZmbZkZoXMML5KwAlkwHN9CQDYU38ch9fBFUYPF0')

# network_requests_test_asset_vulns('https://demo.tfint.link', 'cKj2ZmbZkZoXMML5KwAlkwHN9CQDYU38ch9fBFUYPF0')

network_test_asset_vulns('https://demo.tfint.link', 'cKj2ZmbZkZoXMML5KwAlkwHN9CQDYU38ch9fBFUYPF0')

# network_test_bulk_update_status('https://demo.tfint.link', 'cKj2ZmbZkZoXMML5KwAlkwHN9CQDYU38ch9fBFUYPF0')

# get_vuln_by_id_test('https://demo.tfint.link', 'cKj2ZmbZkZoXMML5KwAlkwHN9CQDYU38ch9fBFUYPF0')
