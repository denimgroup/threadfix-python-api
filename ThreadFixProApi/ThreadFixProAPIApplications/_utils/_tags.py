#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2019 Denim group"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

import requests
import urllib3
import requests.exceptions
import requests.packages.urllib3

from ...API import API

class TagsAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro Tags API instance.
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

    def create_tag(self, name, tag_type="APPLICATION"):
        """
        Creats a new tag with the given name
        :param name: Name to assign the new tag. 60 character limit
        :param tag_type: The type of tag to create
        """
        params = {'name' : name, 'tagType' : tag_type}
        return super().request('POST', 'rest/tags/new', params)

    def get_tag_by_id(self, tag_id):
        """
        Gets tag by the given tagId
        :param tag_id: Tag identifier
        """
        return super().request('GET', 'rest/tags/' + str(tag_id))

    def get_tag_by_name(self, tag_name):
        """
        Gets tag by the given name
        :param tag_name: The name of a tag to be gotten
        """
        return super().request('GET', 'rest/tags/lookup?name=' + str(tag_name))

    def get_tags_by_vulnerability(self, vuln_id):
        """
        Gets tags attached to a given vulnerability
        :param vuln_id: The identifier of the vulnerability to get the tags from
        """
        return super().request('GET', 'rest/tags/vulnerabilities' + str(vuln_id))

    def get_all_tags(self):
        """
        Returns a list of all tags and returns their JSON
        """
        return super().request('GET', 'rest/tags/index')

    def list_tags(self):
        """
        Retrieves a list of only tag names, ids, and types.
        """
        return super().request('GET', 'rest/tags/list')

    def update_tag(self, tag_id, name):
        """
        Updates the name of the tag with the given tagId
        :param tag_id: Tag identifier
        :param name: New name to assign the tag
        """
        params = {'name' : name}
        return super().request('POST', 'rest/tags/' + str(tag_id) + '/update', params)

    def add_tag_to_application(self, application_id, tag_id):
        """
        Attaches the tag with the given tagId to the app with the given appId
        :param application_id: Application identifier
        :param tag_id: Tag identifier
        """
        return super().request('POST', 'rest/applications/' + str(application_id) + '/tags/add/' + str(tag_id))

    def remove_tag_to_application(self, application_id, tag_id):
        """
        Removes the tag with the given tagId to the app with the given appId
        :param application_id: Application identifier
        :param tag_id: Tag identifier
        """
        return super().request('POST', 'rest/applications/' + str(application_id) + '/tags/remove/' + str(tag_id))

    def delete_tag(self, tag_id):
        """
        Deletes the tag with the given tagId
        :params tag_id: Tag identifier
        """
        return super().request('POST', 'rest/tags/' + str(tag_id) + '/delete')

    def list_applications_for_tag(self, tag_id):
        """
        Returns the JSON of the apps that have the tag with the given tagId
        :params tag_id: Tag identifier
        """
        return super().request('GET', 'rest/tags/' + str(tag_id) + '/listApplications')