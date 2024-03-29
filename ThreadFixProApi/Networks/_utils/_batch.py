__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class BatchAPI(API):

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

    def bulk_update_vulnerability_status(self, status, vuln_ids):
        """
        Updates a group of vulnerabilities at once to a new status
        :param status: Vulnerability status to update to
        :param vuln_ids: Vulnerabilities to update
        """
        json = { 'resources' : vuln_ids}
        return super().request('PUT', f'/api/batch/vulnerabilities/status/{status}', json=json)

    def bulk_update_vulnerability_severity(self, severity, vuln_ids):
        """
        Updates a group of vulnerabilities at once to a new severity
        :param severity: Vulnerability severity to update to
        :param vuln_ids: Vulnerabilities to update
        """
        json = { 'resources' : vuln_ids}
        return super().request('PUT', f'/api/batch/vulnerabilities/severity/{severity}', json=json)