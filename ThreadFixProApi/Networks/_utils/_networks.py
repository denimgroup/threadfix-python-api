__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class NetworksAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro API instance.
        :param host: The URL for the ThreadFix Pro server. (e.g., http://localhost:8080) NOTE: must include http:// 
        :param api_key: The API key generated on the ThreadFix Pro API Key page.
        :param verify_ssl: Specify if API requests will verify the host's SSL certificate, defaults to true.
        :param timeout: HTTP timeout in seconds, default is 30.
        :param headers: Headers are done automatically so feel free to leave this as None unless you really need custom headers
        :param user_agent: HTTP user agent string, default is "threadfix_pro_api/[version]".
        :param cert: You can also specify a local cert to use as client side certificate, as a single file (containing
        the private key and the certificate) or as a tuple of both file’s path
        :param debug: Prints requests and responses, useful for debugging.
        """
        super().__init__(host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)

    def create_new_network(self, name, ip_ranges, ip_addresses, description=None, location=None, department=None):
        """
        Creates a new network in ThreadFix
        :param name: Name of network.
        :param ip_ranges: IP range network covers.
        :param ip_addresses: IP addresses network covers.
        :param description: Description of network.
        :param location: Location of network.
        :param department: Department of network.
        """
        params = {'name' : name, 'ipRanges' : ip_ranges, 'ipAddresses' : ip_addresses}
        if description:
            params['description'] = description
        if location:
            params['location'] = location
        if department:
            params['department'] = department
        return super().request('POST', '/api/network/networks', params=params)

    def fetch_all_networks(self, page=1, limit=50, href=None):
        """
        Fetches all networks one page at a time of limit
        :param page: The page of the network to get (optional if you have href)
        :param limit: The amount of networks per page
        :param href: The link to the next page in the system from a previous call
        """
        # If href (calling another page gives an href tag for next page in line)
        if href:
            return super().request('GET', '/api/network' + href)
        # First call
        return super().request('GET', f'/api/network/networks?_page={page}&_limit={limit}')

    def find_network_by_id(self, network_id):
        """
        Gets a network by its id
        :param network_id: ID of the network to get
        """
        return super().request('GET', f'https://localhost/api/network/networks/{network_id}')

    def update_network(self, network_id, name, ip_ranges, ip_addresses, description=None, location=None, department=None):
        """
        Updates an existing network in ThreadFix
        :param network_id: ID of network to update
        :param name: Name of network.
        :param ip_ranges: IP range network covers.
        :param ip_addresses: IP addresses network covers.
        :param description: Description of network.
        :param location: Location of network.
        :param department: Department of network.
        """
        params = {'name' : name, 'ipRanges' : ip_ranges, 'ipAddresses' : ip_addresses}
        if description:
            params['description'] = description
        if location:
            params['location'] = location
        if department:
            params['department'] = department
        return super().request('PUT', f'/api/network/networks/{network_id}', params=params)

    def find_network_by_id(self, network_id):
        """
        Deletes a network by its id
        :param network_id: ID of the network to delete
        """
        return super().request('DELETE', f'https://localhost/api/network/networks/{network_id}')