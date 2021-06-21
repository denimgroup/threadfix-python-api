#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2019 Denim group"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...ThreadFixProResponse import ThreadFixProResponse
from ...API import API

class ApplicationsAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro Applications API instance.
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

    def create_application(self, team_id, name, url=None):
        """
        Creates an application under a given team.
        :param team_id: Team identifier.
        :param name: The name of the new application being created.
        :param url: The url of where the application is located.
        """
        params = {'name': name}
        if url:
            params['url'] = url
        return super().request('POST', '/teams/' + str(team_id) + '/applications/new', params)

    def get_application_by_id(self, application_id):
        """
        Retrieves an application using the given application id.
        :param application_id: Application identifier.
        """
        return super().request('GET', '/applications/' + str(application_id))

    def get_application_by_name(self, team_name, application_name):
        """
        Retrieves an application using the given team name and application name.
        :param team_name: The name of the team of the application to be retrieved.
        :param application_name: The name of the application to be retrieved.
        """
        return super().request('GET',
                             '/applications/' + str(team_name) + '/lookup?name=' + str(application_name))

    def get_application_in_team_by_unique_id(self, team_name, unique_id):
        """
        Retrieves an application using the given team name and the applications unique id
        :param team_name: The name of the team of the application to be retrieved.
        :param unique_id: The unique id of the application to be retrieved.
        """
        return super().request('GET',
                             '/applications/' + str(team_name) + '/lookup?uniqueId=' + str(unique_id))

    def get_application_from_any_team_by_unique_id(self, unique_id):
        """
        Retrieves an application using the applications unique id ignoring team name
        :param unique_id: The unique id of the application to be retrieved.
        """
        return super().request('GET',
                             '/applications/allTeamLookup?uniqueId=' + str(unique_id))

    def update_application(self, application_id, name=None, url=None, unique_id=None, application_criticality=None, framework_type=None, repository_url=None, repository_type=None, repository_branch=None,
                         repository_user_name=None, repository_password=None, repository_folder=None, filter_set=None, team=None, skip_application_merge=None):
        """
        Updates the information of an application. Needs atleast one parameter to work
        :param application_id: Application identifier
        :param name: New name for application
        :param unique_id: New unique id for application
        :param application_criticality: New application criticality for application
        :param framework_type: New framework type for application
        :param repository_url: New repository for application
        :param repository_type: New type of repository, git or SVN, for application
        :param repository _branch: New branch of repository for application
        :param repository_user_name: New username for accessing the repository of the application
        :param repository_password: New password for accessing the repository of the application
        :param repository_folder: New folder for the repository
        :param filter_set: New filter set for application
        :param team: New team for application
        :param skip_application_merge: Whether or not to merge the application
        """
        params = {}
        if name:
            params['name'] = name
        if url:
            params['url'] = url
        if unique_id:
            params['uniqueId'] = unique_id
        if application_criticality:
            params['applicationCriticality'] = application_criticality
        if framework_type:
            params['frameworkType'] = framework_type
        if repository_url:
            params['repositoryUrl'] = repository_url
        if repository_type:
            params['repositoryType'] = repository_type
        if repository_branch:
            params['repositoryBranch'] = repository_branch
        if repository_user_name:
            params['repositoryUserName'] = repository_user_name
        if repository_password:
            params['repositoryPassword'] = repository_password
        if repository_folder:
            params['repositoryFolder'] = repository_folder
        if filter_set:
            params['filterSet'] = filter_set
        if team:
            params['team'] = team
        if skip_application_merge:
            params['skipApplicationMerge'] = skip_application_merge
        return super().request('PUT', '/applications/' + str(application_id) + '/update', params)

    def set_application_parameters(self, framework_type, repository_url, application_id):
        """
        Sets application parameters
        :param framework_type: Sets the webframework the app is built on
        :param repository_url: The location of the repository where the app code can be found
        :param application_id: Application identifier
        """
        params = {'frameworkType' : framework_type, 'repositoryUrl' : repository_url}
        return super().request('POST', '/applications/' + str(application_id) + '/setParameters', params)

    def set_application_WAF(self, waf_id, application_id):
        """
        Sets the WAF id for the application
        :param waf_id: the WAF id for the application
        :param application_id: Application identifier
        """
        params = {'wafId' : waf_id}
        return super().request('POST', '/applications/' + str(application_id) + '/setWaf', params)

    def set_application_URL(self, url, application_id):
        """
        Sets the application URL
        :param url: The url for the application
        :param application_id: Application identifier
        """
        params = {'url' : url}
        return super().request('POST', '/applications/' + str(application_id) + '/addUrl', params)
    
    def add_manual_finding(self,  application_id, vuln_type, long_description, severity, is_static=False, native_id=None, parameter=None, file_path=None, column=None,
                            line_text=None, line_number=None, full_url=None, path=None):
        """
        Adds manual finding to application
        :param application_id: Application identifier
        :param vuln_type: Name of the vulnerability
        :param long_description: General description of the issue
        :param severity: Severity level of vulnerability from 1-5
        :param is_static: Is the finding from a static or dynamic test
        :param native_id: Identifier for the vulnerability
        :param parameter: Requested parameters for vulnerability
        :param file_path: (Static only) Location of source file
        :param column: (Static only) Column number for finding vulnerability source
        :param line_text: (Static only) Line text for finding vulnerability source
        :param line_number: (Static only) Line number for finding vulnerability source
        :param full_url: (Dynamic only) Absolute URL to page with vulnerability
        :param path: (Dynamic only) Relative path to the page with the vulnerability
        """
        params = {'vulnType' : vuln_type, 'long_description' : long_description, 'severity' : severity}
        if native_id:
            params['nativeId'] = native_id
        if parameter:
            params['parameter'] = parameter
        if file_path:
            params['filePath'] = file_path
        if column:
            params['column'] = column
        if line_text:
            params['lineText'] = line_text
        if line_number:
            params['lineNumber'] = line_number
        if full_url:
            params['fullUrl'] = full_url
        if path:
            params['path'] = path
        return super().request('POST', '/applications/' + str(application_id) + 'addFinding', params)

    def create_application_version(self, version_name, version_date, application_id):
        """
        Creates an application version
        :param version_name: Name of the version of the application
        :param version_date: Date of the version of the application
        :param application_id: Application identifier
        """
        params = {'versionName' : version_name, 'versionDate' : version_date}
        return super().request('POST', '/applications/' + str(application_id) + '/version', params)

    def update_application_version(self, application_id, version_id, version_name=None, version_date=None):
        """
        Updates the version data for an application
        :param application_id: Application identifier
        :param version_id: Version identifier
        :param version_name: New name for version
        :param version_date: New date for version
        """
        params = {}
        if version_name:
            params['versionName'] = version_name
        if version_date:
            params['versionDate'] = version_date
        return super().request('PUT', '/applications/' + str(application_id) + '/version/' + str(version_id))
    
    def delete_application_version(self, application_id, version_id):
        """
        Deletes the version data for an application
        :param application_id: Application identifier
        :param version_id: Version identifier
        """
        return super().request('DELETE', '/applications/' + str(application_id) + '/version/' + str(version_id))

    def attach_file_to_application(self, application_id, file_path, file_name=None,):
        """
        Uploads and attaches a file. to an application
        :param application_id: Application identifier.
        :param file_path: Path to the file to be uploaded.
        :param file_name: A name to override the file name when uploaded
        """
        params={}
        if file_name:
            params['filename'] = file_name
        files={'file': open(file_path, 'rb')}
        return super().request('POST', '/applications/' + str(application_id) + '/attachFile', params, files)

    def delete_applications(self, application_id):
        """
        Deletes an application
        :param application_id: Application identifier
        """
        return super().request('DELETE', '/applications/' + str(application_id) + '/delete')

    def create_application_metadata(self, key, title, description, application_id):
        """
        Creates metadata for an application
        :param key: The id of an active Application Metadata Key
        :param title: The name of an active Application Metadata Key
        :param description: The value for the Metadata
        :param application_id: Application identifier
        """
        params = {'key' : key, 'title' : title, 'description' : description}
        return super().request('POST', '/applications/' + str(application_id) + '/metadata/new', params)

    def edit_application_metada(self, description, application_id, app_metadata_id):
        """
        Edits an application's metadata
        :param description: New value for Metadata
        :param application_id: Application identifier
        :param app_metadata_id: Metadata identifier
        """
        params = {'description' : description}
        return super().request('POST', '/applications/' + str(application_id) + '/metadata/' + str(app_metadata_id) + '/update')

    def delete_application_metadata(self, application_id, app_metadata_id):
        """
        Deletes an application's metadata
        :param application_id: Application identifier
        :param app_metadata_id: Metadata identifier
        """
        return super().request('DELETE', '/applications/' + str(application_id) + '/metadata/' + str(app_metadata_id) + '/delete')

    def get_applications_by_team(self, team_id):
        """
        Retrieves all application using the given team id.
        :param team_id: Team identifier.
        """
        team_data = self.get_team_by_id(team_id)
        if team_data.success:
            new_data = []
            for app in team_data.data['applications']:
                new_data.append(app)
            return ThreadFixProResponse(message=team_data.message, success=team_data.success,
                                     response_code=team_data.response_code, data=new_data)
        else:
            return team_data
