#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2019 Denim group"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class PoliciesAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro Policies API instance.
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

    def get_policy(self, policy_id):
        """
        Get details for a policy
        :param policy_id: Policy identifier
        """
        return super().request('GET', 'rest/policies/' + str(policy_id))

    def get_all_policies(self):
        """
        Get a list of all policies in ThreadFix
        """
        return super().request('GET', 'rest/policies')

    def get_application_policy_status(self, application_id):
        """
        Get the status for all policies attached to the application with the provided appId
        :param application_id: Application identifier
        """
        return super().request('GET', 'rest/applications/' + str(application_id) + '/policyStatuses')

    def add_application_to_policy(self, policy_id, application_id):
        """
        Adds an application to a policy
        :param policy_id: Policy identifier
        :param application_id: Application identifier
        """
        return super().request('POST', 'rest/policies/' + str(policy_id) + '/application/' + str(application_id))

    def ad_hoc_policy_evaluation(self, application_id, policy_id):
        """
        Gets the status of a policy even if the policy is not attached to the application
        :param application_id: Application identifier
        :param policy_id: Policy identifier
        """
        return super().request('GET', 'rest/applications/' + str(application_id) + '/policy/eval?policyId=' + str(policy_id))

    def retrieve_all_policies(self, team_id):
        """
        Get details for all policies attached to a team
        :param team_id: Team identifier
        """
        return super().request('GET', 'rest/policies/team/' + str(team_id))

    def add_policy_to_team(self, policy_id, team_id):
        """
        Adds a policy to a team and any application associated with that team
        :param policy_id: Policy identifier
        :param team_id: Team identifier
        """
        return super().request('POST', 'rest/policies/' + str(policy_id) + '/team/' + str(team_id))

    def remove_policy_to_team(self, policy_id, team_id):
        """
        Removes a policy to a team and any application associated with that team
        :param policy_id: Policy identifier
        :param team_id: Team identifier
        """
        return super().request('DELETE', 'rest/policies/' + str(policy_id) + '/team/' + str(team_id) + '/remove')