#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2019 Denim group"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class MiscellaneousAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro Miscellaneous API instance.
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

    def clear_global_fpr_filter_set_override(self):
        """
        Clears the Global FPR Filter Set Override.  The file is still available in the Scan Upload Location if you want to reuse it later.
        """
        return super().request('DELETE', '/defaults/fprfilterset')

    def configure_email_settings(self, host, port, sender, user, password, tls, smtp_authorization, filters=None):
        """
        Sets values for the Email configuration fields
        :param host: Email server hostname
        :param port: Port for email server
        :param sender: Email address Thread Fix emails will be sent from
        :param user: User account to validate email server authorization
        :param password: Password for user account
        :param tls: Set to true to enable tls
        :param smtp_authorization: Set to true to enable SMTP authorization
        :param filters: Comma separated email filters, supports * wildcard. Non matching email addresses will be rejected at sending time for security reasons.
        """
        params = {'host' : host, 'port' : port, 'sender' : sender, 'user' : user, 'password' : password, 'tls' : tls, 'smtpAuthorization' : smtp_authorization}
        if filters:
            params['filter'] = filters
        return super().request('PUT', '/systemsettings/email', params)

    def configure_ldap_settings(self, url, search_base, user_dn, password, name, login_filter=None, users_filter=None, groups_filter=None, users_groups_filter=None):
        """
        Sets the values for the LDAP configuration fields
        :param url: URL for LDAP server
        :param search_base: The point from which ThreadFix will search for LDAP users from
        :param user_dn: User domain name to use for LDAP queries
        :param password: Password for user domain name
        :param name: Name for LDAP server
        :param login_filter: Override filter to get the account of the person logging in
        :param users_filter: Override filter to get the list of users in the directory
        :param groups_filter: Override filter to get the list of groups in the directory
        :param users_groups_filter: Override filter to get the list of groups for a user
        """
        params = {'url' : url, 'searchBase' : search_base, 'userDn' : user_dn, 'password' : password, 'name' : name}
        if login_filter:
            params['loginFilter'] = login_filter
        if users_filter:
            params['usersFilter'] = users_filter
        if groups_filter:
            params['groupsFilter'] = groups_filter
        if users_groups_filter:
            params['usersGroupsFilter'] = users_groups_filter
        return super().request('PUT', '/systemsettings/ldap', params)

    def get_email_confirmation_details(self):
        """
        Returns email configuration fields. Password will always be null
        """
        return super().request('GET', '/systemsettings/email')

    def get_ldap_confirmation_details(self):
        """
        Returns LDAP configuration fields. Password will always be null
        """
        return super().request('GET', '/systemsettings/ldap')

    def set_custom_cwe_text(self, cwe_id, custom_text):
        """
        Sets Custom CWE Text for the provided CWE
        :param cwe_id: CWE identifier
        :param custom_text: The custom text to display in filed defects
        """
        params = {'customText' : custom_text}
        return super().request('POST', '/cwe/' + str(cwe_id) + '/setCustomText', params)

    def upload_global_fpr_filter_set_override(self, file_path):
        """
        Uploads a file to the Scan Upload Location, to be used as an override Filter Set for all Fortify Scans
        :param file_path: Path to scan to upload
        """
        files = {'file' : open(file_path)}
        return super().request('POST', '/defaults/fprfilterset', files=files)

    def create_metadata_key(self, key, keytype, active=True):
        """
        Creates a new metadata key
        :param key: Name of metadata key
        :param keytype: Type of metadata key
        :param active: Whether or not the new key is immediately enabled
        """
        params = {'key' : key, 'type' : keytype, 'active' : active}
        return super().request('POST', '/metadataKeys/new', params)

    def create_metadata_key(self, metadata_key_id, key=None, active=None):
        """
        Edits a new metadata key
        :param metadata_key_id: Metadat Key identifier
        :param key: Name of metadata key
        :param active: Whether or not the new key is immediately enabled
        """
        params = {}
        if key:
            params['key'] = key
        if active:
            params['active'] = active
        return super().request('POST', '/metadataKeys/' + str(metadata_key_id) + '/update', params)

    def get_metadata_keys(self, keytype=None):
        """
        Returns all metadata keys
        :param keytype: Type of Metadata key to return
        """
        if keytype:
            return super().request('GET', '/metadataKeys?type=' + str(keytype))
        else:
            return super().request('GET', '/metadataKeys')