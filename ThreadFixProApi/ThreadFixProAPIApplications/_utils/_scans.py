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

class ScansAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro Scans API instance.
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

    def get_scan_details(self, scan_id):
        """
        List all scans for a given application
        :param scan_id: Scan identifier.
        """
        return super().request('GET', 'rest/scans/' + str(scan_id))

    def list_scans(self, application_id):
        """
        List all scans for a given application
        :param application_id: Application identifier.
        """
        return super().request('GET', 'rest/applications/' + str(application_id) + '/scans')

    def upload_scan(self, application_id, file_path):
        """
        Uploads and processes a scan file.
        :param application_id: Application identifier.
        :param file_path: Path to the scan file to be uploaded.
        """
        return super().request(
            'POST', 'rest/applications/' + str(application_id) + '/upload',
            files={'file': open(file_path, 'rb')}
        )
    
    def multiple_file_scan_upload(self, application_id, file_paths, bulk_upload=False):
        """
        Uploads and processes multiple scan file.
        :param application_id: Application identifier.
        :param file_path: Path to the scan file to be uploaded.
        :param bulk_upload: Upload files as a single scan (False) or separate scans (True)
        """
        return super().request(
            'POST', 'rest/applications/' + str(application_id) + '/upload/multi',
            files= [{'file' : open(file_path, 'rb')} for file_path in file_paths]
        )

    def check_pending_scan_status(self, application_id, scan_id):
        """
        Check the status of a scan after it has been queued
        :param application_id: Application identifier
        :param scan_id: Scan identifier
        """
        return super().request('GET', 'rest/applications/' + str(application_id) + '/pendingScan/' + str(scan_id) + '/status')

    def download_scan(self, scan_id, filename):
        """
        Download a scan by id
        :param scan_id: Scan identifier
        :param filename: Download location
        """
        return super().request('GET', 'rest/scans/' + str(scan_id) + '/download',
                             params={'scanFileName': filename})

    def delete_scan(self, scan_id):
        """
        Queues the specified scan for deletion
        :param scan_id: Scan identifier
        """
        return super().request('DELETE', 'rest/scans/' + str(scan_id) + '/delete')

    def edit_scan_metadata(self, metadata_key_id, key=None, description=None, title=None):
        """
        Updates scan metadata
        :param metadata_key_id:
        :param key: The scan metadata key for the metadata which will be edited
        :param description: New text for description field
        :param title: Scan Metadata key title. Used if key param is not present
        """
        params = {}
        if key:
            params['key'] = key
        if description:
            params['description'] = description
        if title:
            params['title'] = title
        return super().request('POST', 'rest/customize/scanmetadata/keys/' + str(metadata_key_id) + '/update', params)

    def create_scan_metadata(self, scan_id, key, description, title=None):
        """
        Creates new scan metadata
        :param scan_id: Scan identifier
        :param key: The metadata key ID
        :param description: Text description of metadata
        :param title: The scan metadata key title.
        """
        params = {'key' : key, 'description' : description}
        if title:
            params['title'] = title
        return super().request('POST', 'rest/scans/' + str(scan_id) + '/metadata/new', params)

    def delete_scan_metadata(self, scan_id, scan_metadata_key_id):
        """
        Deletes scan metadata from scan
        :param scan_id: Scan identifier
        :param scan_metadata_key_id: Scan Metadata Key identifier
        """
        return super().request('POST', 'rest/scans/' + str(scan_id) + '/metadata/' + str(scan_metadata_key_id) + '/delete')