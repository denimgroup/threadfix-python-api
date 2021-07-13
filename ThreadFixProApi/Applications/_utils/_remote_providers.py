#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2019 Denim group"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from requests import api
from ...API import API

class RemoteProvidersAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro Remote Providers API instance.
        :param host: The URL for the ThreadFix Pro server. (e.g., http://localhost:8080/threadfix/) NOTE: must include http:// TODO: make it so that it is required or implicitly added if forgotten
        :param api_key: The API key generated on the ThreadFix Pro API Key page.
        :param verify_ssl: Specify if API requests will verify the host's SSL certificate, defaults to true.
        :param timeout: HTTP timeout in seconds, default is 30.
        :param user_agent: HTTP user agent string, default is "threadfix_pro_api/[version]".
        :param cert: You can also specify a local cert to use as client side certificate, as a single file (containing
        the private key and the certificate) or as a tuple of both file’s path
        :param debug: Prints requests and responses, useful for debugging.
        """
        super().__init__(host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)

    def add_remote_provider_application_mapping(self, remote_provider_application_id, application_id, report_url=None):
        """
        Maps a ThreadFix application to the Remote Provider application
        :param remote_provider_application_id: Remote Provider Application identifier
        :param application_id: Application identifier
        :param report_url: The version URL to use for Black Duck remote provider application
        """
        params = {'applicationId' : application_id}
        if report_url:
            params['reportUrl'] = report_url
        return super().request('POST', '/remoteprovider/remoteProviderApplication/' + str(remote_provider_application_id) + '/addMapping', params)

    def check_remote_provider_application_import_status(self, remote_provider_application_id):
        """
        Returns the status for the Remote Provider Application import
        :param remote_provider_application_id: Remote Provider Application identifier
        """
        return super().request('GET', '/remoteprovider/remoteProviderApplication/' + str(remote_provider_application_id) + '/status')

    def get_remote_provider_application_versions(self, remote_provider_application_id):
        """
        Returns the status for the Remote Provider Application import
        :param remote_provider_application_id: Remote Provider Application identifier
        """
        return super().request('GET', '/remoteprovider/remoteProviderApplication/' + str(remote_provider_application_id) + '/versions')

    def get_remote_provider_applications(self, team_id=None, remote_provider_id=None, application_id=None, hide_mapped=None, hide_unmapped=None):
        """
        Returns a list of Remote Provider applications as well as the applications they are mapped to
        :param team_id: Team identifier. Returns only results mapped to that team
        :param remote_provider_id: Remote Provider identifier. Return only results that belong to the specified Remote Provider
        :param application_id: Application identifier. Return only results that belong to the specified application
        :param hide_mapped: Does not return results that are already mapped to ThreadFix applications
        :param hide_unmapped: Does not return results that lack a ThreadFix application mapping
        """
        params = {}
        if team_id:
            params['teamId'] = team_id
        if remote_provider_id:
            params['remoteProviderId'] = remote_provider_id
        if application_id:
            params['applicationId'] = application_id
        if hide_mapped:
            params['hideMapped'] = hide_mapped
        if hide_unmapped:
            params['hideUnmapped'] = hide_unmapped
        return super().request('GET', '/remoteprovider/remoteProviderApplication/list', params)

    def get_remote_provider_applications_by_name(self, name, remote_provider_id):
        """
        Gets list of Remote Provider Applications with the provided name
        :param name: Name of the Remote Provider Applications to return
        :param remote_provider_id: ID of a Remote Provider to rict the search to
        """
        params = {'name' : name}
        if remote_provider_id:
            params['remoteProviderId'] = remote_provider_id
        return super().request('GET', '/remoteprovider/remoteProviderApplication/search', params)

    def get_remote_providers(self):
        """
        Returns a list of Remote Providers
        """
        return super().request('GET', '/remoteprovider/list')

    def import_remote_provider_scans(self, remote_provider_application_id):
        """
        Triggers a Remote Provider import for the specified Remote Provider Application
        :param remote_provider_application_id: Remote Provider Application identifier
        """
        return super().request('POST', '/remoteprovider/remoteProviderApplication/' + str(remote_provider_application_id) + '/import')

    def import_remote_provider_all(self, remote_provider_id):
        """
        Triggers a Remote Provider import for all applications from the specified Remote Provide
        :param remote_provider_id: Remote Provider identifier
        """
        return super().request('POST', '/remoteprovider/' + str(remote_provider_id) + '/import')

    #Queue Remote Provider Scan has been left out - https://denimgroup.atlassian.net/wiki/spaces/TDOC/pages/22914237/Queue+Remote+Provider+Scan+-+API

    def remove_remote_provider_application_mapping(self, remote_provider_application_id):
        """
        Removes the ThreadFix application mapping for a Remote Provider application
        :param remote_provider_application_id: Remote Provider Application identifier
        """
        return super().request('DELETE', '/remoteprovider/remoteProviderApplication/' + str(remote_provider_application_id) + '/removeMapping')

    def sync_remote_provider_applications(self, remote_provider_id):
        """
        Syncs ThreadFix Remote Provider Applications for the specified Remote Provider adding new ones and removing any that are no longer present in the Remote Provide
        :param remote_provider_id: Remote Provider identifier
        """
        return super().request('POST', '/remoteprovider/' + str(remote_provider_id) + '/sync')

    def schedule_remote_provider_import(self, scheduling_method, frequency=None, hour=None, minute=None, period=None, day=None, cron_expression=None, remote_provider_id=None, application_id=None, scheduled_timezone=None):
        """
        Schedules a remote provider import by either cron expression or date.
        :param scheduling_method: SELECT or CRON; Method of scheduling the import.
        :param frequency: DAILY or WEEKLY; Required for SELECT scheduling method
        :param hour: Hour to schedule import (1-12); required for SELECT
        :param minute: Minute to schedule import (00-59); required for SELECT
        :param period: AM or PM; required for SELECT
        :param day: Day to schedule import (eg. 'Sunday'); required for SELECT and WEEKLY Frequency
        :param cron_expression: Cron expression string for CRON method
        :param remote_provider_id: The entity ID of the remote provider to be imported. Leave blank to import all remote providers.
        :param application_id: ID for the ThreadFix application to map to the Remote Provider application. Leave blank to import for all applications.
        :param scheduled_timezone: If one is not provided, dafaults to server timezone. Can be used for both CRON and SELECT
        """
        params = {'schedulingMethod' : scheduling_method}
        if frequency:
            params['frequency'] = frequency
        if hour:
            params['hour'] = hour
        if minute:
            params['minute'] = minute
        if period:
            params['period'] = period
        if day:
            params['day'] = day
        if cron_expression:
            params['cronExpression'] = cron_expression
        if remote_provider_id:
            params['remoteProviderId'] = remote_provider_id
        if application_id:
            params['applicationId'] = application_id
        if scheduled_timezone:
            params['scheduledTimezone'] = scheduled_timezone
        return super().request('POST', '/remoteprovider/scheduledImports/add', params)

    def delete_scheduled_remote_provider_import(self, remote_provider_entity_id):
        """
        Deletes a scheduled remote provider import.
        :param remote_provider_entity_id: id of the remote provider scan that is scheduled to be imported
        """
        return super().request('DELETE', '/remoteprovider/scheduledImports/' + str(remote_provider_entity_id) + '/delete')

    def list_scheduled_remote_provider_imports(self):
        """
        Lists all scheduled remote provider imports.
        """
        return super().request('GET', '/remoteprovider/scheduledImports/list')

    def configure_existing_remote_provider(self, remote_provider_entity_id, url=None, name=None, password=None, apikey=None, secretkey=None):
        """
        Updates existing ThreadFix remote provider configuration
        :param remote_provider_entity_id: id of the remote provider to configure
        :param url: Updated URL of the remote provider application.
        :param name: Used if you want to update the name of the remote provider in ThreadFix.
        :param password: Updated password of the remote provider application.
        :param apikey: Updated API key of the remote provider application.
        :param secretkey: Updated secret key value for the remote provider application.
        """
        params = {}
        if url:
            params['url'] = url
        if name:
            params['name'] = name
        if password:
            params['password'] = password
        if apikey:
            params['ApiKey'] = apikey
        if secretkey:
            params['SecretKey'] = secretkey
        return super().request('POST', '/remoteprovider/' + str(remote_provider_entity_id) + '/configure', params)