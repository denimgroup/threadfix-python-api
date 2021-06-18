#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2019 Denim group"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class TeamsAPI(API):

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

    def create_team(self, name):
        """
        Creates a new team
        :param name: The name of the new team being created
        """
        params = {"name": name}
        return super().request('POST', 'rest/teams/new', params, debug=self.debug)

    def get_team_by_id(self, team_id):
        """
        Retrieves team with id of team_id'
        :param team_id: ID of the team being gotten
        """
        return super().request('GET', 'rest/teams/' + str(team_id))

    def get_team_by_name(self, team_name):
        """
        Retrieves team with name of team_name
        :param team_name: Name of the team being gotten
        """
        return super().request('GET', 'rest/teams/lookup?name=' + str(team_name))

    def get_all_teams(self):
        """
        Retrieves all the teams.
        """
        return super().request('GET', 'rest/teams')

    def update_team(self, team_id, name):
        """
        Updates team with teamId
        :param team_id: Team identifier
        :param name: New name to assign to the team
        """
        params = {'name' : name}
        return super().request('PUT', 'rest/teams/' + str(team_id) + '/update', params)

    def get_team_event_history(self, team_id, pages=None, page_size=None):
        """
        Lists event history for a team
        :param team_id: Team identifier
        :param pages: Number of events to return. By default this method will return up to 10 events
        :param page_size: Can be used to return a different page of events, with each page of events containing page_size events
        """
        params = {}
        if pages:
            params['page'] = pages
        if page_size:
            params['pageSize'] = page_size
        return super().request('POST', 'rest/events/organization/' + str(team_id), params)

    def delete_team(self, team_id):
        """
        Deletes a team by the provided teamId
        :param team_id: Team identifier
        """
        return super().request('DELETE', 'rest/teams/' + str(team_id) + '/delete')