#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class SystemCustomizationAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro Teams API instance.
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

    def add_new_deny_or_allow_list_entry(self, channel_type_id, channel_type_name, channel_vulnerability_id, channel_vulnerability_name):
        """
        Creates a new deny list or allow list entry for a scanner
        :param channel_type_id: The ID of the channel type.
        :param channel_type_name: The name of the channel type (e.g. Checkmarx, Black Duck, etc.). Required if channel_type_id not used.
        :param channel_vulnerability_id: The ID of the channel vulnerability
        :param channel_vulnerability_name: The name of the channel vulnerability. Required if channel_vulnerability_id not used.
        """
        params = {}
        if channel_type_id:
            params['channelTypeId'] = channel_type_id
        if channel_type_name:
            params['channelTypeName'] = channel_type_name
        if channel_vulnerability_id:
            params['channelVulnerabilityId'] = channel_vulnerability_id
        if channel_vulnerability_name:
            params['channelVulnerabilityName'] = channel_vulnerability_name
        return super().request('POST', '/scanner/denyListAllowList/new', params)

    def change_deny_or_allow_list_mode(self, channel_type_id, channel_type_name, list_mode):
        """
        Allows user to change from current mode to new mode
        :param channel_type_id: The ID of the channel type.
        :param channel_type_name: The name of the channel type (e.g. Checkmarx, Black Duck, etc.). Required if channel_type_id not used.
        :param list_mode: Either 'denyList' or 'allowList'
        """
        params = {}
        if channel_type_id:
            params['channelTypeId'] = channel_type_id
        if channel_type_name:
            params['channelTypeName'] = channel_type_name
        if list_mode:
            params['listMode'] = list_mode
        return super().request('POST', '/scanner/denyListAllowList/setListMode', params)

    def delete_deny_or_allow_list_entry(self, list_id):
        """
        Allows user to delete a deny list or allow list item from a channel
        :param list_id: Id of the list to delete
        """
        return super().request('DELETE', '/scanner/denyListAllowList/' + str(list_id) + '/delete')