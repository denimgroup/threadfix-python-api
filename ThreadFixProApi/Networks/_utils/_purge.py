__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class PurgeAPI(API):

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

    def queue_scan_for_purge(self, scan_id):
        """
        Queues a scan to be purged
        :param scan_id: ID of scan to be purged
        """
        return super().request('DELETE', f'/api/purge/scans/{scan_id}')

    def queue_scans_for_purge(self, scan_ids):
        """
        Queues a set of scans to be purged
        :param scan_ids: IDs of scans to be purged
        """
        params = { 'resources' : scan_ids }
        return super().request('DELETE', f'/api/purge/scans', params=params)

    def queue_asset_for_purge(self, asset_id):
        """
        Queues an asset to be purged
        :param asset_id: ID of asset to be purged
        """
        return super().request('DELETE', f'/api/purge/assets/{asset_id}')

    def queue_assets_for_purge(self, asset_ids):
        """
        Queues a set of assets to be purged
        :param asset_ids: IDs of assets to be purged
        """
        params = { 'resources' : asset_ids }
        return super().request('DELETE', f'/api/purge/assets', params=params)