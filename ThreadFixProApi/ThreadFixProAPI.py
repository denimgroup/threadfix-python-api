#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Brandon Spruth (bspruth@gmail.com), Jim Nelson (jim.nelson2@target.com),"
__copyright__ = "(C) 2018 Target Brands, Inc."
__contributors__ = ["Brandon Spruth", "Jim Nelson", "Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from .API import API

from .Applications import ThreadFixProAPIApplications
from .Networks import ThreadFixProAPINetworks

class ThreadFixProAPI(API):
    """An API wrapper to facilitate interactions to and from ThreadFix for both Applications and Networks."""

    def __init__(self, host, api_key, verify_ssl=True, timeout=30, headers=None, user_agent=None, cert=None, debug=False):
        """
        Initialize a ThreadFix Pro API instance.
        :param host: The URL for the ThreadFix Pro server. (e.g., http://localhost:8080/threadfix) NOTE: must include http:// TODO: make it so that it is required or implicitly added if forgotten
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
        # Add on threadfix to application calls to make sure it can still work in a unified system as application endpoints are on /threadfix/{endpoint}
        self.Applications = ThreadFixProAPIApplications(self.host + '/threadfix', api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.Networks = ThreadFixProAPINetworks(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
