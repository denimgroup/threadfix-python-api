#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2019 Denim group"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class UsersRolesAndGroupsAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro Users Roles and Groups API instance.
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

    def add_application_role_to_group(self, group_id, app_id, role_id):
        """
        Gives the group permissions in the provided role for the specified application
        :param group_id: Group identifier
        :param app_id: Application identifier
        :param role_id: Role identifier
        """
        params = {'appId' : app_id, 'roleId' : role_id}
        return super().request('POST', '/groups/' + str(group_id) + '/role/app', params)

    def add_application_role_to_user(self, user_id, app_id, role_id):
        """
        Gives the user permissions in the provided role for the specified application
        :param user_id: User identifier
        :param app_id: Application identifier
        :param role_id: Role identifier
        """
        params = {'appId' : app_id, 'roleId' : role_id}
        return super().request('POST', '/users/' + str(user_id) + '/role/app', params)

    def add_team_role_to_group(self, group_id, team_id, role_id):
        """
        Gives the group permissions in the provided role for the specified team and all its application
        :param group_id: Group identifier
        :param team_id: Team identifier
        :param role_id: Role identifier
        """
        params = {'teamId' : app_id, 'roleId' : role_id}
        return super().request('POST', '/groups/' + str(group_id) + '/role/team', params)

    def add_team_role_to_user(self, user_id, team_id, role_id):
        """
        Gives the group permissions in the provided role for the specified team and all its application
        :param user_id: User identifier
        :param team_id: Team identifier
        :param role_id: Role identifier
        """
        params = {'teamId' : app_id, 'roleId' : role_id}
        return super().request('POST', '/users/' + str(user_id) + '/role/team', params)

    def get_groups(self):
        """
        Returns a list of groups
        """
        return super().request('GET', '/groups/list')

    def get_roles(self):
        """
        Returns a list of roles
        """
        return super().request('GET', '/roles/list')

    def get_users(self):
        """
        Returns a list of users
        """
        return super().request('GET', '/users/list')

    def edit_user(self, user_id, name=None, display_name=None, user_type=None, active_directory_id=None, password=None, confirm_password=None, global_role_id=None):
        """
        Updates user information
        :param user_id: User identifier
        :param name: New name for user
        :param display_name: New display name for user
        :param user_type: Updates a LOCAL user to LDAP/SAML, an LDAP user to LOCAL/SAML, or a SAML user to LOCAL/LDAP. Possible values are LOCAL, LDAP, and SAML
        :param active_directory_id: Updates a non-LDAP user to LDAP user with 'type' and 'activeDirectoryId' parameters. Required when 'type' is in the request body and its value is 'LDAP'
        :param password: New password for the existing user
        :param confirm_password: Must match password if supplied
        :param global_role_id: New global role for user
        """
        params = {}
        if name:
            params['name'] = name
        if display_name:
            params['displayName'] = display_name
        if user_type:
            params['type']  = user_type
        if active_directory_id:
            params['activeDirectoryId'] = active_directory_id
        if password:
            params['password'] = password
        if confirm_password:
            params['confirmPassword'] = confirm_password
        if global_role_id:
            params['globalRoleId'] = global_role_id
        return super().request('POST', '/users/' + str(user_id) + '/update', params)

    def remove_application_role_from_group(self, group_id, app_id):
        """
        Removes the group permissions for the specified application
        :param group_id: Group identifier
        :param app_id: Application identifier
        """
        params = {'appId' : app_id}
        return super().request('POST', '/groups/' + str(group_id) + '/role/app/delete', params)

    def remove_application_role_from_user(self, user_id, app_id):
        """
        Removes the user permissions for the specified application
        :param user_id: User identifier
        :param app_id: Application identifier
        """
        params = {'appId' : app_id}
        return super().request('POST', '/users/' + str(user_id) + '/role/app/delete', params)

    def remove_team_role_from_group(self, group_id, team_id):
        """
        Removes the group permissions for the specified team
        :param group_id: Group identifier
        :param team_id: Team identifier
        """
        params = {'teamId' : team_id}
        return super().request('POST', '/groups/' + str(group_id) + '/role/team/delete', params)

    def remove_team_role_from_user(self, user_id, team_id):
        """
        Removes the user permissions for the specified team
        :param user_id: User identifier
        :param team_id: Team identifier
        """
        params = {'teamId' : team_id}
        return super().request('POST', '/users/' + str(user_id) + '/role/team/delete', params)

    def create_user(self, name, user_type, display_name=None, active_directory_id=None, password=None, confirm_password=None, global_role_id=None):
        """
        Updates user information
        :param name: Name for user
        :parm user_type: "Local" if adding a local user; "LDAP" if adding an LDAP user.
        :param display_name: Display name for user
        :param active_directory_id: Required when 'type' value is "LDAP".
        :param password: Password for the existing user
        :param confirm_password: Must match password if supplied
        :param global_role_id: Global role for user
        """
        params = {'name' : name, 'type' : user_type}
        if display_name:
            params['displayName'] = display_name
        if active_directory_id:
            params['activeDirectoryId'] = active_directory_id
        if password:
            params['password'] = password
        if confirm_password:
            params['confirmPassword'] = confirm_password
        if global_role_id:
            params['globalRoleId'] = global_role_id
        return super().request('POST', '/users/new', params)

    def delete_user(self, user_id):
        """
        Deletes user from the system
        :param user_id: User identifier
        """
        return super().request('DELETE', '/users/' + str(user_id) + '/delete')

    def create_group(self, name, active_directory_id=None, global_role_id=None):
        """
        Adds a group to the system
        :param name: Name of group being added
        :param active_directory_id: Required when adding an LDAP group
        :param global_role_id: Adds the group's global role
        """
        params = {'name' : name}
        if active_directory_id:
            params['activeDirectoryId'] = active_directory_id
        if global_role_id:
            params['globalRoleId'] = global_role_id
        return super().request('POST', '/groups/new' , params)

    def edit_group(self, group_id, name, global_role_id=None):
        """
        Updates the specified group in the system
        :param group_id: Group identifier
        :param name: Updates name of group
        :param global_role_id: Adds or changes the group's global role
        """
        params = {'name' : name}
        if global_role_id:
            params['globalRoleId'] = global_role_id
        return super().request('POST', '/groups/' + str(group_id) + '/update' , params)

    def delete_group(self, group_id):
        """
        Deletes the specified group from the system
        :param group_id: Group identifier
        """
        return super().request('DELETE', '/groups/' + str(group_id) + '/delete')

    def import_ldap_users(self, active_directory_id, import_ldap_groups=None):
        """
        Adds LDAP users to system
        :param active_directory_id: Active directory from which to import
        :param import_ldap_groups: Enable to import groups from the active directory
        """
        params = {'activeDirectoryId' : active_directory_id}
        if import_ldap_groups:
            params['importLdapGroups'] = import_ldap_groups
        return super().request('POST', '/users/importLdapUsers', params)

    def prune_ldap_users(self, active_directory_id):
        """
        Removes pruned LDAP users from the system
        :param active_directory_id: Active directory from which users are removed
        """
        params = {'activeDirectoryId' : active_directory_id}
        return super().request('POST', '/users/pruneLdapUsers', params)

    def add_user_to_group(self, group_id, user_id):
        """
        Adds a user to the specified group.
        :param group_id: Group identifer
        :param user_id: User identifier to add to group
        """
        return super().request('POST', '/groups/' + str(group_id) + '/addUser/' + str(user_id))

    def add_user_to_group(self, group_id, user_id):
        """
        Removees a user to the specified group.
        :param group_id: Group identifer
        :param user_id: User identifier to add to group
        """
        return super().request('POST', '/groups/' + str(group_id) + '/removeUser/' + str(user_id))

    def export_users_audit_csv_report(self):
        """
        Returns a CSV report of all users, which includes groups and roles.
        """
        return super().request('GET', '/users/export/csv')

    def user_audit(self):
        """
        Returns a list of users and associated groups and roles
        """
        return super().request('GET', '/users/audit')

    def get_login_history_for_all_users(self, page=10, number_to_show=20):
        """
        Returns login history of all users
        :param page: Number of events to return. By default this method will return up to 10 events.
        :param number_to_show: 	Can be used to return a different page of events, with each page of events containing {numberToShow} events. * If not specified, the default limit is 20
        """
        params = {'page' : page, 'numberToShow' : number_to_show}
        return super().request('POST', '/history/userLogins', params)

    def get_event_history_for_all_users(self, page=10, number_to_show=20):
        """
        Returns global event history of all users
        :param page: Number of events to return. By default this method will return up to 10 events.
        :param number_to_show: 	Can be used to return a different page of events, with each page of events containing {numberToShow} events. * If not specified, the default limit is 20
        """
        params = {'page' : page, 'numberToShow' : number_to_show}
        return super().request('POST', '/history/history/objects', params)