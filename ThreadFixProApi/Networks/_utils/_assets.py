__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class AssetsAPI(API):

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

    def create_new_asset(self, name, ip_addresses, description=None, os_family=None, os_name=None, os_version=None, public_facing=None, archived=None, mac_addresses=None, fqdns=None):
        """
        Creates a new asset for ThreadFix
        :param name: Name of the asset.
        :param ip_addresses: IP addresses the asset applies to.
        :param description: Description of the asset.
        :param os_family: Name of the family of operating systems this asset applies to.
        :param os_name: Name of the os this asset applies to.
        :param os_version: Version of the os this asset applies to.
        :param public_facing: Whether or not the asset is public facing.
        :param archived: Whether or not the asset is archived.
        :param mac_addresses: List of mac addresses the asset applies to.
        :param fqdns: List of DNS addresses the asset applies to.
        """
        params = {'name' : name, 'ipAddresses' : ip_addresses}
        if description:
            params['description'] = description
        if os_family:
            params['osFamily']
        if os_name:
            params['osName'] = os_name
        if os_version:
            params['osVersion'] = os_version
        if public_facing is not None:
            params['publicFacing'] = public_facing
        if archived is not None:
            params['archived'] = archived
        if mac_addresses:
            params['macAddresses'] = mac_addresses
        if fqdns:
            params['fqdns'] = fqdns
        return super().request('POST', '/api/network/assets', params=params)

    def fetch_all_assets(self, page=1, limit=50, href=None):
        """
        Fetches all assets a page at a time with search parameters
        :param page: The page of the vulnerability to get (optional if you have href)
        :param limit: The amount of vulnerabilities per page
        :param href: The link to the next page in the system from a previous call
        TODO Figure out filters
        """
        params = {}
        # If href (calling another page gives an href tag for next page in line)
        if href:
            return super().request('GET', '/api/network' + href, params=params)
        return super().request('GET', f'/api/network/assets?_page={page}&_limit={limit}', params=params)

    def find_asset_by_id(self, asset_id):
        """
        Gets an asset by its id
        :param asset_id: ID of asset to get
        """
        return super().request('GET', f'/api/network/assets/{asset_id}')

    def update_an_existing_asset(self, asset_id, name, ip_addresses, description=None, os_family=None, os_name=None, os_version=None, public_facing=None, archived=None, mac_addresses=None, fqdns=None):
        """
        Updates an existing asset for ThreadFix
        :param asset_id: ID of asset to update
        :param name: Name of the asset.
        :param ip_addresses: IP addresses the asset applies to.
        :param description: Description of the asset.
        :param os_family: Name of the family of operating systems this asset applies to.
        :param os_name: Name of the os this asset applies to.
        :param os_version: Version of the os this asset applies to.
        :param public_facing: Whether or not the asset is public facing.
        :param archived: Whether or not the asset is archived.
        :param mac_addresses: List of mac addresses the asset applies to.
        :param fqdns: List of DNS addresses the asset applies to.
        """
        params = {'name' : name, 'ipAddresses' : ip_addresses}
        if description:
            params['description'] = description
        if os_family:
            params['osFamily']
        if os_name:
            params['osName'] = os_name
        if os_version:
            params['osVersion'] = os_version
        if public_facing is not None:
            params['publicFacing'] = public_facing
        if archived is not None:
            params['archived'] = archived
        if mac_addresses:
            params['macAddresses'] = mac_addresses
        if fqdns:
            params['fqdns'] = fqdns
        return super().request('PUT', f'/api/network/assets/{asset_id}', params=params)

    def delete_an_asset(self, asset_id):
        """
        Deletes an asset
        :param asset_id: ID of asset to delete
        """
        return super().request('DELETE', f'/api/network/assets/{asset_id}')