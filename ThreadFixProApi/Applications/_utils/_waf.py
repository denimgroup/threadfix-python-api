#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2019 Denim group"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class WafsAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro WAFs API instance.
        :param host: The URL for the ThreadFix Pro server. (e.g., http://localhost:8080/threadfix/) NOTE: must include http:// TODO: make it so that it is required or implicitly added if forgotten
        :param api_key: The API key generated on the ThreadFix Pro API Key page.
        :param verify_ssl: Specify if API requests will verify the host's SSL certificate, defaults to true.
        :param timeout: HTTP timeout in seconds, default is 30.
        :param user_agent: HTTP user agent string, default is "threadfix_pro_api/[version]".
        :param cert: You can also specify a local cert to use as client side certificate, as a single file (containing
        the private key and the certificate) or as a tuple of both file’s path
        :param debug: Prints requests and responses, useful for debugging.
        """
        super().__init__(host, api_key, verify_ssl, timeout, user_agent, cert, debug)

    def create_waf(self, name, WAFtype):
        """
        Creates a WAF with the given name and type
        :param name: Name for the WAF
        :param WAFtype: Type of WAF you are creating
        """
        params = {'name' : name, 'type' : WAFtype}
        return super().request('POST', '/wafs/new', params)

    def get_waf_by_id(self, waf_id):
        """
        Gets a WAF by the WAFId
        :param waf_id: WAF identifier
        """
        return super().request('GET', '/wafs/' + str(waf_id))

    def get_waf_by_name(self, waf_name):
        """
        Gets a WAF by its name
        :param waf_name: The name of the WAF being gotten
        """
        return super().request('GET', '/wafs/lookup?name=' + str(waf_name))

    def get_all_wafs(self):
        """
        Gets all WAFs in the system
        """
        return super().request('GET', '/wafs')

    def get_waf_rules(self, waf_id, app_id):
        """
        Returns the WAF rule text for one or all applications a WAF is attached to. If the appId is -1, it will get rules for all apps. 
        If the appId is a valid application ID, rules will be generated for that application.'
        :param waf_id: WAF identifier
        :param app_id: Application identifier
        """
        return super().request('GET', '/wafs/' + str(waf_id) + '/rules/app/' + str(app_id))

    def upload_waf_log(self, waf_id, file_path):
        """
        Uploads WAF log
        :param waf_id: WAF identifier
        :param file_path: Path to file to be uploaded
        """
        files = {'file' : open(file_path, 'rb')}
        return super().request('POST', '/wafs/' + str(waf_id) + '/uploadLog', files=files)