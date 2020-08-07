#!/usr/bin/python
# Copyright 2020 Jack Consoli.  All rights reserved.
#
# NOT BROADCOM SUPPORTED
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may also obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`user_config.py` - Example on how to create a user.

Whether using the examples contained herein or working with advanced features, you should familiarize yourself with the
"Managing User Accounts" in the FOS Admin Guide, "brocade-security" in the Rest API Guide, brocade-security.yang, and
brocade-security-types.yang before attempting to create, delete, or modify user accounts. Although written as a stand
alone utility, it's probably only useful as an example to get you started. Most customers use an authentication server
and these examples are for RBAC user accounts only.

Examples::

    # Delete the test_admin account:
    py user_config.py -ip 10.8.105.10 -id admin -pw password -a d -nid test_admin

WARNING::

    It was intended that all modules in api_direct require only libraries that are part of the standard Python
    download. This module requires collections. The exception was made here because I believe requiring an ordered
    dictionary is a FOS defect and will be fixed in some future version of FOS.

Important Notes::

    FOS does not permit changes to the root account via the API. This was tested with FOS 8.2.1c and 8.2.2. I could not
    get password changes to work with either version of FOS. That doesn't mean FOS has a defect. I could be doing
    something wrong. I needed to post this for to illustrate other aspects of managing user accounts so I just added a
    warning if someone tries to change a password.

    +---------------------------+-----------------------------------------------------------------------------------+
    | area                      | Comments                                                                          |
    +===========================+===================================================================================+
    | account-locked            | Not supported with POST. I don't think it's supported with PATCH either. I think  |
    |                           | this is a read only (GET) field                                                   |
    +---------------------------+-----------------------------------------------------------------------------------+
    | account-description       | Returns an error with PATCH. I think this is a defect to be addressed in a future |
    |                           | release of FOS. It works with POST                                                |
    +---------------------------+-----------------------------------------------------------------------------------+
    | name                      | I'm not sure if the order of other parameters is important but name must be       |
    |                           | first. Since the only way I can ensure that name is first in the content sent to  |
    |                           | the switch, I put everything else in the same order as specified in the REST API  |
    |                           | Guide. Unless you happen to get lucky, this means you can't build the content by  |
    |                           | mimicking the response from user-config with GET.                                 |
    +---------------------------+-----------------------------------------------------------------------------------+
    | password                  | The login password must be in plain text. Assuming you are using HTTPS, this will |
    |                           | be encrypted on the wire.                                                         |
    |                           | When creating or changing a user password, the password must be base64 encoded.   |
    |                           | password is not supported with method PATCH within the user-config leaf. There is |
    |                           | a seperate leaf, password, which does support PATCH that is used for changing     |
    |                           | passwords.                                                                        |
    |                           | Some changes to the implementation of the root password have been introduced in   |
    |                           | that may preclude the ability to log in as root from the API.                     |
    |                           | An account login with higher access right can change parameters of a lower level  |
    |                           | account but not vice versa. For example, the default admin can modify both the    |
    |                           | default admin and default user passwords but the default user can only change the |
    |                           | default user password.                                                            |
    +---------------------------+-----------------------------------------------------------------------------------+
    | Radius/LDAP/tacacs        | I did not have access to a Radius, LDAP, or TACACS server. Note that configuring  |
    |                           | users remote authentication will require leaves radius-server, tacacs-server,     |
    |                           | or ldap-server. Although similar approaches should apply, only RBAC examples are  |
    |                           | contained herein.                                                                 |
    +---------------------------+-----------------------------------------------------------------------------------+

Version Control::

    +-----------+---------------+-----------------------------------------------------------------------------------+
    | Version   | Last Edit     | Description                                                                       |
    +===========+===============+===================================================================================+
    | 1.0.0     | 05 Mar 2020   | Initial. Does not support password changes.                                       |
    +-----------+---------------+-----------------------------------------------------------------------------------+
"""
__author__ = 'Jack Consoli'
__copyright__ = 'Copyright 2020 Jack Consoli'
__date__ = '05 Mar 2020'
__license__ = 'Apache License, Version 2.0'
__email__ = 'jack.consoli@broadcom.com'
__maintainer__ = 'Jack Consoli'
__status__ = 'Development'
__version__ = '1.0.0'

from pprint import pprint
import os
import base64
import brcdapi.brcdapi_rest as brcdapi_rest
import brcdapi.pyfos_auth as pyfos_auth
import brcdapi.log as brcdapi_log
import argparse
import collections

_DOC_STRING = False  # Should always be False. Prohibits any actual I/O. Only useful for building documentation
_DEBUG = True  # When True, use _DEBUG_xxx parameters below instead of passed arguments
_DEBUG_IP = '10.8.105.10'
_DEBUG_ID = 'admin'
_DEBUG_PW = 'password'
_DEBUG_SEC = 'none'
_DEBUG_SUPPRESS = False
_DEBUG_ACTION = 'm'
_DEBUG_USER_ID = 'test_admin'  # This is the user ID we are taking action on
_DEBUG_USER_PW = None  # This is the new password for _DEBUG_USER_ID when changing a user account password.
_DEBUG_OLD_PW = None  # This is the current password for _DEBUG_USER_ID when changing a user account
_DEBUG_USER_ROLE = None  # ['admin=1-128']
_DEBUG_HOME_FID = 128  # This is the home FID when a user logs in (an int 1-128). If None, home is the default FID
_DEBUG_CID = None  # This is the user to clone
_DEFAULT_DESC = None  # 'Test user account'
_DEBUG_END_TIME = None
_DEBUG_START_TIME = None
_DEBUG_ENABLED = None
_DEBUG_LOCKED = None
_DEBUG_CHASSIS_ROLE = None  # 'admin'
_DEBUG_PW_CHANGE = None  # False
_DEBUG_NON_VF_ROLE = None

_BAD_EXIT_STATUS = -1
_GOOD_EXIT_STATUS = 0

# The table below contains all the leaves that I think should be changeable (PATCH). Those that are not supported are
# handled by the methods in _user_config_case. 'account-description' should be supported but was not in the versions of
# FOS tested (8.2.1c, 8.2.1d, 8.2.2, 8.2.2a)
# TO DO - Why is 'name' not in _supported_patch
_supported_patch = ('name', 'access-end-time', 'access-start-time', 'account-enabled',
                    'account-locked', 'chassis-access-role', 'home-virtual-fabric', 'password-change-enforced',
                    'role', 'virtual-fabric-role-id-list')
_supported_post = ('name', 'access-end-time', 'access-start-time', 'account-enabled', 'account-description',
                   'chassis-access-role', 'home-virtual-fabric', 'password-change-enforced',
                   'role', 'virtual-fabric-role-id-list')


def version():
    """Returns the module version number

    :return: Version
    :rtype: str
    """
    return __version__


def _login(ip, user_id, pw, sec):
    """Basically the main().

    :param user_id: User ID
    :type user_id: str
    :param pw: Password
    :type pw: str
    :param ip: IP address
    :type ip: str
    :param sec: Security. 'none' for HTTP, 'self' for self signed certificate, 'CA' for signed certificate
    :type sec: str
    :return: Session object. None if login failed
    :rtype: dict, None
    """
    # Login
    brcdapi_log.log('Attempting login', True)
    session = brcdapi_rest.login(user_id, pw, ip, sec)
    if pyfos_auth.is_error(session):
        brcdapi_log.log('Login failed', True)
        brcdapi_log.log(pyfos_auth.formatted_error_msg(session), True)
        return None
    else:
        brcdapi_log.log('Login succeeded', True)
        return session


# Below make up the case statements used in _user_config_case. Each has the same parameters:
# old_obj   None, dict. If not None, this is the object we're copying.
# k         str. This is the item key
# v         This is the new value to add to the content
def _add_new_only(old_obj, k, v):
    # Only add the key if v is not None
    if v is None:
        return False, None, None
    else:
        return True, v, None


def _add_new_first(old_obj, k, v):
    # If v is not None, return v as the value. Otherwise return the item from old_obj if it's not None
    if v is None:
        val = None if old_obj is None else old_obj.get(k)
        if val is None:
            return False, val, None
        else:
            return True, val, None
    else:
        return True, v, None


def _add_new_first_abs(old_obj, k, v):
    # Same as _add_new_first() but if v is None, return the old value no matter what it is.
    return True, old_obj.get(k) if v is None else v, None


def _add_new_first_ns(old_obj, k, v):
    # Same as _add_new_first_abs() but return a value of None and no add flag if old value is ''
    if v is None:
        val = None if old_obj is None else old_obj.get(k)
        if isinstance(val, str) and len(val) == 0:
            val = None
        if val is None:
            return False, val, None
        else:
            return True, val, None
    else:
        return True, v, None


def _add_vf_role_abs(old_obj, k, v):
    return True, {'role-id': old_obj.get('virtual-fabric-role-id-list').get('role-id') if v is None else v}, None


def _must_have(old_obj, k, v):
    if v is None:
        return False, None, 'Required parameter, ' + k + ', is missing'
    else:
        return True, v, None


def _add_role(old_obj, k, v):
    # user-config will return an error if 'role', non-vf role, is not present. VF enabled switches, however, do not
    # return 'role' in the GET so default it to the old chassis role and if that's not available, default to 'user'.
    # Ideally, I would default to the current chassis role but making that available in this method for such an odd
    # case isn't worth the effort.
    flag, test_v, buf = _add_new_first(old_obj, k, v)
    if buf is None and (not flag or test_v is None):
        if old_obj is not None and old_obj.get('chassis-access-role') is not None:
            test_v = old_obj.get('chassis-access-role')
            brcdapi_log.log('Non-VF role, \'role\' not specified. Defaulting to old \'chassis-access-role\'', True)
    if test_v is None:
        test_v = 'user'
        brcdapi_log.log('Could not resolve Non-VF chassis role. Setting \'role\' to ' + test_v, True)
    flag = True
    return flag, test_v, buf


def _null(old_obj, k, v):
    return False, None, None


def _unsupported_patch(old_obj, k, v):
    # This method was created to capture unsupported operations during development. There shouldn't be any way to get
    # here with a released version of this module.
    return True, None, 'Unsupported key, ' + k + ' for PATCH'


def _unsupported_post(old_obj, k, v):
    # This method was created to capture unsupported operations during development. There shouldn't be any way to get
    # here with a released version of this module.
    return True, None, 'Unsupported key, ' + k + ' for POST'


_user_config_case = collections.OrderedDict()
_user_config_case['name'] = {'POST': _must_have, 'PATCH': _must_have}
_user_config_case['password'] = {'POST': _must_have, 'PATCH': _unsupported_patch}
_user_config_case['role'] = {'POST': _add_role, 'PATCH': _null}
_user_config_case['account-description'] = {'POST': _add_new_first_abs, 'PATCH': _unsupported_patch}
_user_config_case['account-enabled'] = {'POST': _add_new_first_abs, 'PATCH': _add_new_only}
_user_config_case['password-change-enforced'] = {'POST': _add_new_first_abs, 'PATCH': _add_new_only}
_user_config_case['account-locked'] = {'POST': _unsupported_post, 'PATCH': _add_new_only}
_user_config_case['home-virtual-fabric'] = {'POST': _add_new_first_abs, 'PATCH': _add_new_only}
_user_config_case['virtual-fabric-role-id-list'] = {'POST': _add_vf_role_abs, 'PATCH': _add_new_only}
_user_config_case['chassis-access-role'] = {'POST': _add_new_first_abs, 'PATCH': _add_new_only}
_user_config_case['access-end-time'] = {'POST': _add_new_first_abs, 'PATCH': _add_new_only}
_user_config_case['access-start-time'] = {'POST': _add_new_first_abs, 'PATCH': _add_new_only}


def _get_user(session, id):

    """GET a copy of a user

    :param session: Session object returned from brcdapi.pyfos_auth.login()
    :type session: dict
    :param id: User ID to find
    :type id: str, None (returns None if id is None)
    :return: Dictionary returned from GET if found, otherwise None
    :rtype: dict, None
    """
    uri = 'brocade-security/user-config'
    if id is not None:
        # Get all configured users from the switch and find the one to copy
        obj = brcdapi_rest.get_request(session, uri)
        if pyfos_auth.is_error(obj):
            brcdapi_log.log(pyfos_auth.formatted_error_msg(obj), True)
            return False
        for temp_obj in obj.get('user-config'):
            if temp_obj.get('name') == id:
                return temp_obj
    return None


def _create_user(session, inp):

    """Creates a new user

    :param session: Session object returned from brcdapi.pyfos_auth.login()
    :type session: dict
    :param inp: Dictionary of input parameters.
    :type inp: dict
    :return: True - Suceeded, False - Failed
    :rtype: bool
    """
    method = 'POST'
    check_l = {'PATCH': _supported_patch, 'POST': _supported_post}
    check = check_l.get(method)

    # Set up the request to create the new user to send to the switch
    default_obj = _get_user(session, inp.get('_default'))
    if default_obj is None:
        brcdapi_log.log('Could not find user ' + inp.get('_default') + ' to clone')
        return _BAD_EXIT_STATUS
    new_obj = collections.OrderedDict()
    for k in _user_config_case.keys():
        if k in check:
            flag, val, buf = _user_config_case[k][method](default_obj, k, inp[k])
            if buf is not None:
                brcdapi_log.log(buf, True)
                return _BAD_EXIT_STATUS
            if flag:
                new_obj[k] = val

    # Now send it
    response = brcdapi_rest.send_request(session, 'brocade-security', method, {'user-config': [new_obj]})
    if pyfos_auth.is_error(response):
        brcdapi_log.log('Failed to create user:\n' + pyfos_auth.formatted_error_msg(response), True)
        return _BAD_EXIT_STATUS
    return _GOOD_EXIT_STATUS


def _delete_user(session, inp):
    """Deletes a user

    :param session: Session object returned from brcdapi.pyfos_auth.login()
    :type session: dict
    :param inp: Dictionary of input parameters.
    :type inp: dict
    :return: True - Suceeded, False - Failed
    :rtype: bool
    """
    new_obj = collections.OrderedDict()
    new_obj['name'] = inp['name']  # 'name' is a required input parameter so no need for any checking

    response = brcdapi_rest.send_request(session, 'brocade-security', 'DELETE', {'user-config': [new_obj]})
    if pyfos_auth.is_error(response):
        brcdapi_log.log('Failed to delete user: ' + inp['name'] + '\n' + pyfos_auth.formatted_error_msg(response), True)
        return _BAD_EXIT_STATUS
    return _GOOD_EXIT_STATUS


def _test_delete_user(session, inp):
    """Deletes a user

    :param session: Session object returned from brcdapi.pyfos_auth.login()
    :type session: dict
    :param inp: Dictionary of input parameters.
    :type inp: dict
    :return: True - Suceeded, False - Failed
    :rtype: bool
    """
    uri = 'brocade-security/user-config'
    # Get all configured users from the switch but skip the one to delete
    obj = brcdapi_rest.get_request(session, uri)
    if pyfos_auth.is_error(obj):
        brcdapi_log.log(pyfos_auth.formatted_error_msg(obj), True)
        return False
    print('\nUsers read from chassis:')
    pprint(obj)
    found_flag = False
    l = []  # List of users to keep
    method = 'PATCH'
    print('\nMethod: ' + method)
    print('\nUsers to keep:')
    for temp_obj in obj.get('user-config'):
        if temp_obj.get('name') == inp['name']:
            found_flag = True
#            print('TP_200')
        else:
            new_obj = collections.OrderedDict()
#            new_obj['name'] = temp_obj.get('name')
#            new_obj['role'] = temp_obj.get('name')
            for k in _user_config_case.keys():
                if k in ('access-end-time', 'access-start-time'):
                    continue
                if k in _supported_patch:
                    flag, val, buf = _user_config_case[k][method](new_obj, k, temp_obj.get(k))
                    if buf is not None:
                        brcdapi_log.log(buf, True)
                        return _BAD_EXIT_STATUS
                    if flag:
                        new_obj[k] = val
            if method == 'POST':
                new_obj['role'] = temp_obj.get('name')
            pprint(new_obj)
            l.append(new_obj)

    # Send all the users to keep
    if len(l) > 0 and found_flag:
        response = brcdapi_rest.send_request(session, 'brocade-security', 'PATCH', {'user-config': l})
        if pyfos_auth.is_error(response):
            brcdapi_log.log('Failed to delete user:\n' + pyfos_auth.formatted_error_msg(response), True)
            return _BAD_EXIT_STATUS
        return _GOOD_EXIT_STATUS
    else:
        brcdapi_log.log('Delete use ' + str(inp['name']) + ' failed. User not found')
        return _BAD_EXIT_STATUS

    new_obj = collections.OrderedDict()
    new_obj['name'] = inp['name']  # 'name' is a required input parameter so no need for any checking

    response = brcdapi_rest.send_request(session, 'brocade-security', 'DELETE', {'user-config': [new_obj]})
    if pyfos_auth.is_error(response):
        brcdapi_log.log('Failed to create user:\n' + pyfos_auth.formatted_error_msg(response), True)
        return _BAD_EXIT_STATUS
    return _GOOD_EXIT_STATUS


def _modify_user(session, inp):
    """Modifies a user

    :param session: Session object returned from brcdapi.pyfos_auth.login()
    :type session: dict
    :param inp: Dictionary of input parameters.
    :type inp: dict
    :return: True - Suceeded, False - Failed
    :rtype: bool
    """
    method = 'PATCH'
    change_flag = False

    # Process all non-password related changes. Password changes use brocade-security/password
    default_obj = _get_user(session, inp.get('_default'))
    new_obj = collections.OrderedDict()
    for k in _user_config_case.keys():
        if k in _supported_patch:
            flag, val, buf = _user_config_case[k][method](default_obj, k, inp[k])
            if buf is not None:
                brcdapi_log.log(buf, True)
                return False
            if flag:
                change_flag = True
                new_obj[k] = val
    if change_flag:
        # Now send it
        response = brcdapi_rest.send_request(session, 'brocade-security/user-config', method, [new_obj])
        if pyfos_auth.is_error(response):
            brcdapi_log.log('Failed to modify user:\n' + pyfos_auth.formatted_error_msg(response), True)
            return _BAD_EXIT_STATUS

    # See if the password is changing. I probably could have sent both the previous changes and this change in the
    # same request but time is not of the essence with user changes so I kept it simple.
    # WARNING: I could not get the password change to work no matter what I did
    new_pw = inp.get('password')
    old_pw = inp.get('old-password')
    if new_pw is not None and old_pw is not None:
        new_pw = str(inp.get('password'))
        old_pw = str(inp.get('old-password'))
        brcdapi_log.log('Password changes were experimental at the time this was written.', True)
        change_flag = True
        new_obj = collections.OrderedDict()
        new_obj['user-name'] = inp.get('name')
        new_obj['old-password'] = old_pw
        new_obj['new-password'] = new_pw
        response = brcdapi_rest.send_request(session, 'brocade-security/password', method, new_obj)
        if pyfos_auth.is_error(response):
            brcdapi_log.log('Failed to change password:\n' + pyfos_auth.formatted_error_msg(response), True)
            return _BAD_EXIT_STATUS

    if change_flag:
        return _GOOD_EXIT_STATUS
    else:
        brcdapi_log.log('Nothing to change', True)
        return _BAD_EXIT_STATUS


_action_tbl = {
    'create': _create_user,
    'c': _create_user,
    'delete': _delete_user,
    'del': _delete_user,
    'd': _delete_user,
    'm': _modify_user,
    'mod': _modify_user,
}


def parse_args():
    """Parses the module load command line

    :return ip_addr: IP address
    :rtype ip_addr: str
    :return id: User ID
    :rtype id: str
    :return pw: Password
    :rtype pw: str
    :return file: Name of output file
    :rtype file: str
    :return http_sec: Type of HTTP security
    :rtype http_sec: str
    :return suppress_flag: True - suppress all print to STD_OUT
    :rtype suppress_flag: bool
    """
    if _DEBUG:
        user_pw = None if _DEBUG_USER_PW is None else base64.b64encode(_DEBUG_USER_PW.encode())
        old_pw = None if _DEBUG_OLD_PW is None else base64.b64encode(_DEBUG_OLD_PW.encode())
        user_parameters = {  # Except '_default', these all map to the FOS API names
            '_default': _DEBUG_CID,
            'account-description': _DEFAULT_DESC,
            'access-end-time': _DEBUG_END_TIME,
            'access-start-time': _DEBUG_START_TIME,
            'account-enabled': _DEBUG_ENABLED,
            'account-locked': _DEBUG_LOCKED,
            'chassis-access-role': _DEBUG_CHASSIS_ROLE,
            'home-virtual-fabric': _DEBUG_HOME_FID,
            'name': _DEBUG_USER_ID,
            'old-password': old_pw,
            'password': user_pw,
            'password-change-enforced': _DEBUG_PW_CHANGE,
            'role': _DEBUG_NON_VF_ROLE,
            'virtual-fabric-role-id-list': _DEBUG_USER_ROLE,
        }
        return _DEBUG_IP, _DEBUG_ID, _DEBUG_PW, _DEBUG_SEC, _DEBUG_SUPPRESS, _DEBUG_ACTION, user_parameters
    else:
        buf = 'Create, delete, or modify a user. Must have admin or root access to create a new user. For additional ' \
            'information, read the section "Managing User Accounts" in the Fabric OS Admin Guide.'
        parser = argparse.ArgumentParser(description=buf)
        parser.add_argument('-ip', help='IP address', required=True)
        parser.add_argument('-id', help='Login User ID', required=True)
        parser.add_argument('-pw', help='Login Password', required=True)
        parser.add_argument('-s', help='\'CA\' or \'self\' for HTTPS mode. Default is None (HTTP)', required=False,)
        buf = 'Suppress all library generated output to STD_IO except the exit code. Useful with batch processing'
        parser.add_argument('-sup', help=buf, action='store_true', required=False)
        buf = 'Action. Must be: (c | create) | (d | del | delete) | (m | mod)'
        parser.add_argument('-a', help=buf, required=True)
        buf = '(Optional) User ID to copy. These are the values to use when a value is not explicitly present in the ' \
            'command line. You can use this with create or modify. Passwords are not read so you cannot use this to ' \
            'copy passwords.'
        parser.add_argument('-cid', help=buf, required=False)
        parser.add_argument('-nid', help='User ID to create, delete or modify.', required=True)
        parser.add_argument('-npw', help='(Optional) New user password', required=False)
        parser.add_argument('-opw', help='(Optional) Old password. Required when changing passwords', required=False)
        parser.add_argument('-nr', help='(Optional) user switch role permissions', required=False)
        parser.add_argument('-cr', help='(Optional) user chassis role permissions', required=False)
        parser.add_argument('-nonvfr', help='(Optional) Non-VF role permissions', required=False)
        parser.add_argument('-desc', help='(Optional) user account description', required=False)
        buf = '(Optional) Access end time. Default is no access time restrictions when creating user accounts and no '\
              'change when modifying user accounts.'
        parser.add_argument('-end', help=buf, required=False)
        parser.add_argument('-start', help=buf, required=False)
        buf = '(Optional) Not a command line flag. You must specify true or false when setting this parameter. When '\
              'not specified, '
        buf1 = buf + 'enable state is not changed'
        parser.add_argument('-enable', help=buf1, required=False)
        buf1 = buf + 'locked state is not changed'
        parser.add_argument('-lock', help=buf1, required=False)
        buf1 = buf + 'no change is made. When True, the user will be required to change their password on the next ' \
            'login.'
        parser.add_argument('-pc', help=buf1, required=False)
        parser.add_argument('-home', help='(Optional) Home fabric ID. Default is the default FID', required=False)
        args = parser.parse_args()
        user_parameters = {  # Except '_default', these all map to the FOS API names
            '_default': args.cid,
            'account-description': args.desc,
            'access-end-time': args.end,
            'access-start-time': args.start,
            'account-enabled': args.enable,
            'account-locked': args.lock,
            'chassis-access-role': args.cr,
            'home-virtual-fabric': args.home,
            'name': args.nid,
            'password': None if args.npw is None else base64.b64encode(args.npw.encode()),
            'old-password': None if args.opw is None else base64.b64encode(args.opw.encode()),
            'password-change-enforced': args.pc,
            'role': args.nonvfr,
            'virtual-fabric-role-id-list': args.nr,
        }
        return args.ip, args.id, args.pw, args.s, args.sup, args.a, user_parameters


def pseudo_main():
    """Basically the main().

    :return: Exit code
    :rtype: int
    """
    # Get and condition the command line input
    ip, user_id, pw, sec, s_flag, action, user_parms = parse_args()
    if s_flag:
        brcdapi_log.set_suppress_all()
    if sec is None:
        sec = 'none'
    buf = os.path.basename(__file__) + ' version: ' + version()
    if _DEBUG:
        buf += '\nWARNING!!! Debug is enabled'
    buf += '\nAction: ' + action + '\nUser:   ' + user_id + '\nAdditional parameters:'
    for k in user_parms:
        if k not in ('password, ', 'old-password'):
            buf += '\n  -' + k + ' ' + str(user_parms.get(k))
    brcdapi_log.log(buf, True)

    # Login
    session = _login(ip, user_id, pw, sec)
    if session is None:
        return _BAD_EXIT_STATUS

    # Perform the action
    if action in _action_tbl:
        try:
            ec = _action_tbl[action](session, user_parms)
        except:
            brcdapi_log.exception('Software fault performing ' + action, True)
            ec = _BAD_EXIT_STATUS
    else:
        brcdapi_log.log('Invalid action: ' + action, True)
        ec = _BAD_EXIT_STATUS

    # Logout
    obj = brcdapi_rest.logout(session)
    if pyfos_auth.is_error(obj):
        brcdapi_log.log('Logout failed:\n' + pyfos_auth.formatted_error_msg(obj), True)
        ec = _BAD_EXIT_STATUS

    return ec

###################################################################
#
#                    Main Entry Point
#
###################################################################


if _DOC_STRING:
    print('_DOC_STRING is True. No processing')
else:
    brcdapi_log.close_log(str(pseudo_main()), True, True)
