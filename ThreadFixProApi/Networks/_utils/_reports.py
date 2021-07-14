__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class ReportsAPI(API):

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

    def get_most_vulnerable_networks(self):
        """
        Gets the most vulnerable networks
        """
        return super().request('GET', '/api/report/most-vulnerable-networks')

    def get_most_vulnerable_hosts(self):
        """
        Gets the most vulnerable hosts
        """
        return super().request('GET', '/api/report/most-vulnerable-hosts')

    def get_average_time_to_remediate_report(self):
        """
        Gets the average remediation time.
        """
        return super().request('GET', '/api/report/average-remediation-time')

    def get_most_prevalent_cves_report(self):
        """
        Gets a report of the most common CVEs in ThreadFix
        """
        return super().request('GET', '/api/report/most-prevalent-cves')

    def get_operating_system_report(self):
        """
        Gets the list of operating systems and their information
        """
        return super().request('GET', '/api/report/operating-systems')

    def get_vulnerability_activity_report(self):
        """
        Shows the activity report for each vulnerability
        """
        return super().request('GET', '/api/report/vulnerability-activity-report')

    def get_trending_vulnerability_report(self):
        """
        Shows trending vulnerabilities.
        """
        return super().request('GET', '/api/report/trending-vulnerabilities')