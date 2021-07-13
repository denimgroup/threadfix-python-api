#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

import requests

from ._utils import *
from ..API import API

class ThreadFixProAPINetworks(API):
    """An API wrapper to facilitate interactions to and from ThreadFix specifically for applications."""

    def __init__(self, host, api_key, verify_ssl=True, timeout=30, headers=None, user_agent=None, cert=None, debug=False):
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
        # Initialize network system
        super().__init__(host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        # Create session for next calls
        ret = requests.request('GET', f'{self.host}/auth/apikey', headers={'apikey' : api_key}, verify=False)
        # Build headers. If they don't exist ad tehm
        if not headers:
            # Custom headers for network only
            self.headers = {
                "Content-Type" : "application/json",
                "API-Version" : "1.0",
                "Authorization" : "Bearer " + ret.headers['Set-Cookie']
            }
        else:
            # If from the combined object, add these for the network side
            self.headers['Content-Type'] = "application/json"
            self.headers['API-Version'] = "1.0"
            self.headers['Authorization'] = "Bearer " + ret.headers['Set-Cookie']

        # Link up functions. Uses self to ind to the modification done before to inputs
        self.ActuatorAPI = ActuatorAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.ArchiveAPI = ArchiveAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.AssetsAPI = AssetsAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.BatchAPI = BatchAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.ChannelsAPI = ChannelsAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.DefectTrackerAPI = DefectTrackerAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.FindingsAPI = FindingsAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.ImporterAPI = ImporterAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.NetworksAPI = NetworksAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.ProviderAPI = ProviderAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.PurgeAPI = PurgeAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.ReportsAPI = ReportsAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.SamlAPI = SamlAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.ScansAPI = ScansAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.SearchAPI = SearchAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.SessionsAPI = SessionsAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
        self.VulnerabilitiesAPI = VulnerabilitiesAPI(self.host, self.api_key, self.verify_ssl, self.timeout, self.headers, self.user_agent, self.cert, self.debug)
