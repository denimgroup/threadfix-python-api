#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Brandon Spruth (bspruth@gmail.com), Jim Nelson (jim.nelson2@target.com),"
__copyright__ = "(C) 2018 Target Brands, Inc."
__contributors__ = ["Brandon Spruth", "Jim Nelson", "Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ._utils import *
from ..API import API

class ThreadFixProAPIApplications(API):
    """An API wrapper to facilitate interactions to and from ThreadFix specifically for applications."""

    def __init__(self, host, api_key, verify_ssl=True, timeout=30, headers=None, user_agent=None, cert=None, debug=False):
        """
        Initialize a ThreadFix Pro API instance.
        :param host: The URL for the ThreadFix Pro server. (e.g., http://localhost:8080/threadfix) NOTE: must include http://
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
        # Add versioning
        self.add_versioning()
        self.TeamsAPI = TeamsAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.ApplicationsAPI = ApplicationsAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.DefectTrackersAPI = DefectTrackersAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.PoliciesAPI = PoliciesAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.ScansAPI = ScansAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.TagsAPI = TagsAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.TasksAPI = TasksAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.VulnerabilitiesAPI = VulnerabilitiesAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.WafsAPI = WafsAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.CICDAPI = CICDAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.RemoteProvidersAPI = RemoteProvidersAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.UsersRolesAndGroupsAPI = UsersRolesAndGroupsAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.EmailReportingAPI = EmailReportingAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.MiscellaneousAPI = MiscellaneousAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
        self.SystemCustomizationAPI = SystemCustomizationAPI(self.host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)
