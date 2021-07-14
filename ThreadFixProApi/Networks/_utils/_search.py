__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class SearchAPI(API):

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

    def get_scan_stats_for_system(self):
        """
        Gets scan statistics for the ThreadFix system
        """
        return super().request('GET', '/api/search/scans/stats')

    def get_asset_vulnerability_statistic_by_severity_using_ips(self, page=1, limit=50, href=None, severity=None, status=None, first_found_date=None, last_seen_date=None, ip_address=None):
        """
        Get number of vulnerabilities for each severity by using ips 
        :param page: Page of results to get
        :param limit: Number of results per page
        :param href: The link to the next page in the system from a previous call
        :param severity: Severity of vulnerabilities to get
        :param first_found_date: Get vulnerabilities found on this date
        :param last_seen_date: Get vulnerabilities last seen on this date
        :param ip_address: IP addresses to filter vulnerabilities with
        """
        params = {}
        if severity:
            params['severity'] = severity
        if status:
            params['status'] = status
        if first_found_date:
            params['firstFoundDate'] = first_found_date
        if last_seen_date:
            params['lastSeenDate'] = last_seen_date
        if ip_address:
            params['ipAddress'] = ip_address
        if href:
            return super().request('GET', '/api/search/assets/ipAddresses/vulnerabilities' + href)
        return super().request('GET', f'/api/search/assets/ipAddresses/vulnerabilities/counts?_page={page}&_limit={limit}', params=params)

    def get_asset_vulnerability_details(self, page=1, limit=50, href=None, severity=None, status=None, first_found_date=None, last_seen_date=None, ip_address=None, 
                                        include_stats=False, port=None, cve=None, cvss=None):
        """
        Get all the details from a vulnerability
        :param page: Page of results to get
        :param limit: Number of results per page
        :param href: The link to the next page in the system from a previous call
        :param severity: Severity of vulnerabilities to get
        :param first_found_date: Get vulnerabilities found on this date
        :param last_seen_date: Get vulnerabilities last seen on this date
        :param ip_address: IP addresses to filter vulnerabilities with
        :param include_stats: Whether or not to return the severity counts of vulnerabilities
        :param port: Find vulnerabilities based on the port value
        :param cve: Find vulnerabilities related to this cve
        :param cvss: Find vulnerabilities related to this cvss
        """
        params = { 'includeStats' : include_stats }
        if severity:
            params['severity'] = severity
        if status:
            params['status'] = status
        if first_found_date:
            params['firstFoundDate'] = first_found_date
        if last_seen_date:
            params['lastSeenDate'] = last_seen_date
        if ip_address:
            params['ipAddress'] = ip_address
        if port:
            params['port'] = port
        if cve:
            params['cve'] = cve
        if cvss:
            params['cvss'] = cvss
        if href:
            return super().request('GET', '/api/search/assets/ipAddresses/vulnerabilities' + href)
        return super().request('GET', f'/api/search/assets/ipAddresses/vulnerabilities/counts?_page={page}&_limit={limit}', params=params)

    def get_asset_vulnerability_details_using_ip(self, page=1, limit=50, href=None, severity=None, status=None, first_found_date=None, last_seen_date=None, ip_address=None, include_stats=False):
        """
        Get all the details from a vulnerability
        :param page: Page of results to get
        :param limit: Number of results per page
        :param href: The link to the next page in the system from a previous call
        :param severity: Severity of vulnerabilities to get
        :param first_found_date: Get vulnerabilities found on this date
        :param last_seen_date: Get vulnerabilities last seen on this date
        :param ip_address: IP addresses to filter vulnerabilities with
        :param include_stats: Whether or not to return the severity counts of vulnerabilities
        """
        params = { 'includeStats' : include_stats }
        if severity:
            params['severity'] = severity
        if status:
            params['status'] = status
        if first_found_date:
            params['firstFoundDate'] = first_found_date
        if last_seen_date:
            params['lastSeenDate'] = last_seen_date
        if ip_address:
            params['ipAddress'] = ip_address
        if href:
            return super().request('GET', '/api/search/assets/ipAddresses/vulnerabilities' + href)
        return super().request('GET', f'/api/search/assets/ipAddresses/vulnerabilities/counts?_page={page}&_limit={limit}', params=params)

    def fetch_networks_for_asset(self, asset_id, page=1, limit=50, href=None):
        """
        Gets all networks connected to that asset
        :param asset_id: ID of asset to fetch networks for
        :param page: Page of results to get
        :param limit: Number of results per page
        :param href: The link to the next page in the system from a previous call
        """
        if href:
            super().request('GET', f'/api/search/assets/{asset_id}' + href)
        return super().request('GET', f'/api/search/assets/{asset_id}/networks?_page={page}&_limit={limit}')

    def fetch_assets_for_network(self, network_id, is_archived=False, page=1, limit=50, href=None):
        """
        Gets all assets connected to that network
        :param network_id: ID of asset to fetch networks for
        :param is_archived: Filters assets based on archival status
        :param page: Page of results to get
        :param limit: Number of results per page
        :param href: The link to the next page in the system from a previous call
        """
        params  = { 'isArchived' : is_archived }
        if href:
            super().request('GET', f'/api/search/network/{network_id}' + href, params=params)
        return super().request('GET', f'/api/search/network/{network_id}/networks?_page={page}&_limit={limit}', params=params)