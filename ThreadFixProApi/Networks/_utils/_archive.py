__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class ArchiveAPI(API):

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

    def archive_asset(self, asset_id):
        """
        Archives a specific asset
        :param asset_id: ID of asset to archive
        """
        return super().request('PUT', f'/api/archive/assets/{asset_id}')

    def archive_asset(self, asset_ids):
        """
        Archives a set of assets
        :param asset_ids: IDs of assets to archive
        """
        params = { 'resources' : asset_ids }
        return super().request('PUT', f'/api/archive/assets', params=params)

    def archive_asset(self, asset_id):
        """
        Unarchives a specific asset
        :param asset_id: ID of asset to unarchive
        """
        return super().request('PUT', f'/api/unarchive/assets/{asset_id}')

    def archive_asset(self, asset_ids):
        """
        Unarchives a set of assets
        :param asset_ids: IDs of assets to unarchive
        """
        params = { 'resources' : asset_ids }
        return super().request('PUT', f'/api/unarchive/assets', params=params)