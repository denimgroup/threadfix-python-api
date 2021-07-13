__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class ChannelsAPI(API):

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

    def fetch_all_channels(self, page=1, limit=50, href=None):
        """
        Fetches all channels one page at a time of limit 
        :param page: The page of the channels to get (optional if you have href)
        :param limit: The amount of channels per page
        :param href: The link to the next page in the system from a previous call
        """
        # If href (calling another page gives an href tag for next page in line)
        if href:
            return super().request('GET', '/api/network' + href)
        # First call
        return super().request('GET', f'/api/network/channels?_page={page}&_limit={limit}')

    def find_channel_by_id(self, channel_id):
        """
        Gets a channel by its id
        :param channel_id: ID of the channel to get
        """
        return super().request('GET', f'/api/network/channels/{channel_id}')