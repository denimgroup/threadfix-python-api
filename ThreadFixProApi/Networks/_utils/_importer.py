__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class ImporterAPI(API):

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

    def queue_scan_upload(self, file_path):
        """
        Queues a scan for upload
        :param file_path: Path to the scan file to be uploaded.
        """
        return super().request('POST', '/api/importer', files={'file': open(file_path, 'rb')})

    def import_latest_scan_for_remote_provider(self, provider_id):
        """
        Imports the latest scan into the remote provider specified
        :param provider_id: ID of remote provider to import the scan to.
        """
        return super().request('POST', f'/api/importer/remoteprovider/{provider_id}/importLatest')

    def request_latest_scan_or_ececute_scan_for_provider(self, provider_id):
        """
        Gets the latests scan or executes it for the provider
        :param provider_id: ID of remote provider to import the scan to.
        """
        return super().request('POST', f'/api/importer/remoteprovider/{provider_id}/requestScan')