#!/usr/bin/env python
"""
Reads config from ini config file
and interacts with phpIpam API.

maintained by REndicott
"""

# third party imports
import ConfigParser
import json
import logging
import os
import sys

import requests
from requests.auth import HTTPBasicAuth


# project specific imports
import imports
import loaders
from classes.Runtime import Runtime
from classes.GlobalConfig import GlobalConfig
from classes.Section import Section
from classes.Subnet import Subnet
from classes.Token import Token
from classes.Address import Address
from classes.CustomAttribute import CustomAttribute
from classes.CustomAttribute import CustomFilter

requests.packages.urllib3.disable_warnings()

sversion = 'v1.0'
scriptfilename = os.path.basename(sys.argv[0])
defaultlogfilename = scriptfilename + '.log'


def setuplogging(loglev, printtostdout, logfile):
    """
    pretty self explanatory. Takes options and sets up logging.
    :param loglev:
    :param printtostdout:
    :param logfile:
    :return: None
    """
    logging.basicConfig(filename=logfile,
                        filemode='w', level=loglev,
                        format='%(asctime)s:%(levelname)s:%(message)s')
    if printtostdout:
        soh = logging.StreamHandler(sys.stdout)
        soh.setLevel(loglev)
        logger = logging.getLogger()
        logger.addHandler(soh)


def authenticate(settings, session):
    """
    Reads credentials from settings and authenticates to the
    phpIpam API and returns a Session object with token
    information.
    :param settings:
    :param session:
    :return: session
    """
    # first see if token even needs to be updated
    try:
        if not session.token.is_expired():
            return session
    except:
        # build our headers and perform basic authentication via user/pass
        headers = {'Content-Type': 'application/json'}
        r = requests.post(settings.url_user,
                          headers=headers,
                          verify=False,
                          auth=HTTPBasicAuth(
                              str(settings.username),
                              str(settings.password)
                          )
                          )
        string_token = str(r.json().get('data').get('token'))
        string_expiry = str(r.json().get('data').get('expires'))
        session.token = Token(string_token, string_expiry)
        return session


def create_section(settings, session):
    """
    Interacts with the phpIpam API and creates a new section.
    :param settings:
    :param session:
    :return:
    """
    pass
    '''
    url_sections = str(settings.url_app) + '/sections/'
    headers = {'app_id': str(settings.app),
               'Content-Type': 'application/json',
               'content': 'application/json',
               'token': str(session.token)  # calling token will auto-validate freshenss
               }
    newSection = Section('Automation')
    newSection.permissions = ('{"2":"2","3":"1"}')
    body = {}
    newSection.convert_json()
    json_prop = json.dumps(newSection.dict_props)
    '''
    # print(json_prop)
    # r = requests.post(url_sections,headers=headers,data=json_prop)
    # print(r.content)


def dump_ansible(list_addresses):
    """
    Runs through the list of Address objects and finds associated ID's
    then spits out the ansible inventory format.
    :param list_addresses:
    :return: msg
    """
    '''
    Sample JSON output:
    (http://docs.ansible.com/ansible/developing_inventory.html)
        {
        "databases"   : {
            "hosts"   : [ "host1.example.com", "host2.example.com" ],
            "vars"    : {
                "a"   : true
            }
        },
        "webservers"  : [ "host2.example.com", "host3.example.com" ],
        "atlanta"     : {
            "hosts"   : [ "host1.example.com", "host4.example.com", "host5.example.com" ],
            "vars"    : {
                "b"   : false
            },
            "children": [ "marietta", "5points" ]
        },
        "marietta"    : [ "host6.example.com" ],
        "5points"     : [ "host7.example.com" ]
        }
    '''
    '''
    More sample similar to our data structure:
    {
    "DOANS06": {
    "hosts": [
            "10.119.6.89",
            "10.119.6.10"
        ],
    "vars": {
            "some_attr": "hehehehehe"
        }
    }

    },
    "DODHCP01": [
        "10.119.6.10"
    ],
    "DOORS04": [
        "10.119.6.23"
    ]
    }
    hname = 'DOANS06'
    lh = ['10.119.6.89','10.119.6.10']
    var = { 'some_attr': "hehehehehe" }

    d = { hname : { 'hosts': lh, 'vars': var } }
    j = json.dumps(d, indent=4)

    '''
    hostnames_completed = []
    master_dict = {}
    for address in list_addresses:
        if address.filter_included:
            if address.hostname_short in hostnames_completed:
                continue
            else:
                others = list()
                if len(address.related_ids) > 0:
                    for address_inner in list_addresses:
                        if address_inner.id in address.related_ids and address_inner.id != address.id:
                            others.append(address_inner.ip)
                addresses = list()
                addresses.append(address.ip)
                for ip in others:
                    addresses.append(ip)
                additional_vars = {}
                # loop through the known custom attributes of the address
                for attr in address.custom_attributes:
                    a = attr.attribute_name
                    v = getattr(address, a)
                    # make a dictionary out of the key/value
                    additional_vars[a] = v
                hname = address.hostname_short
                master_dict[hname] = {'hosts': addresses, 'vars': additional_vars}
                hostnames_completed.append(address.hostname_short)
    message = json.dumps(master_dict, indent=4)
    logging.info(message)
    print(message)


def create_subnet_test(settings, session):
    """
    Creates a new Subnet() object then calls
    the API to create it in the default section.
    :param settings:
    :param session:
    :return: None
    """
    url_section = str(settings.url_app) + '/subnets/'
    logging.debug(url_section)
    headers = {'app_id': str(settings.app),
               'Content-Type': 'application/json',
               'content': 'application/json',
               'token': str(session.token)  # calling token will auto-validate freshenss
               }
    s_test = Subnet('192.168.2.0/24')
    s_test.sectionId = session.default_section_id
    s_test.convert_json()
    json_prop = json.dumps(s_test.dict_props)
    r = requests.post(url_section, headers=headers, data=json_prop, verify=False)
    logging.debug(r.content)


def process_config(filename):
    """
    Processes the config INI file and returns a Settings
    object.
    :param filename:
    :return: settings
    """
    logging.debug('------- ENTERING FUNCTION: process_config() -------')
    try:
        cfg = ConfigParser.ConfigParser()
        cfg.read(filename)
        base_url = cfg.get('global', 'base_url')
        app = cfg.get('global', 'app_id')
        username = cfg.get('global', 'username')
        password = cfg.get('global', 'password')
        settings = GlobalConfig(base_url, app, username, password)
        default_section = cfg.get('global', 'default_section')
        settings.default_section = default_section
        try:
            hostname_validation = cfg.get('global', 'hostname_validation')
            if hostname_validation.lower() == 'false' or hostname_validation == '0':
                settings.hostname_validation = False
        except:
            pass
        try:
            settings.filter_subnet = cfg.get('global', 'filter_subnet')
        except:
            settings.filter_subnet = None
        try:
            igsubs = cfg.get('ansible', 'export_ignore_subnets').split(',')
            settings.ansible_ignore_subnets = igsubs
        except:
            pass
        try:
            ighosts = cfg.get('ansible', 'export_ignore_hostnames').split(',')
            settings.ansible_ignore_hostnames = ighosts
        except:
            pass
        # begin section to handle custom attributes
        try:
            custom_attributes = []
            logging.debug('-_-_-_-_-_-_-_ Total number of sections = ' + str(len(cfg.sections())))
            for section in cfg.sections():
                logging.debug('-_-_-_-_-_-_-_ Looping through sections. Current Section = ' + str(section))
                if 'custom_attribute_' in section:
                    cattr = CustomAttribute()
                    cattr.attribute_name = cfg.get(section, 'attribute_name')
                    cattr.attribute_type = cfg.get(section, 'attribute_type')
                    cattr.attribute_default_value = cfg.get(section, 'attribute_default_value')
                    custom_attributes.append(cattr)
            settings.custom_attributes = custom_attributes
        except Exception as err:
            message = "Exception processing custom attributes: " + str(err)
            logging.debug(message)
        # now that we have custom attributes lets see if we should filter any of them
        try:
            custom_filters = []
            for section in cfg.sections():
                if 'custom_filter_' in section:
                    cfilter = CustomFilter()
                    cfilter.attribute_name = cfg.get(section, 'attribute_name')
                    cfilter.attribute_desired_value = cfg.get(section, 'attribute_desired_value')
                    custom_filters.append(cfilter)
            settings.custom_filters = custom_filters
        except Exception as incp:
            message = "Exception processing custom filters: " + str(incp)
            logging.error(message)
    except Exception as orr:
        logging.critical("Exception processing config: " + str(orr))
        sys.exit(1)

    '''
    # sample of how to loop through sections unknown
    for section in cfg.sections():
        if section != 'global':
            job = Job()
            job.name = cfg.get(section,'name')
            job.input_file = cfg.get(section,'input_file')
    '''
    return settings


def claim_address(settings, session, claimipstring, capsv):
    """
    Claims the address and hostname given in 'claimipstring'
    which should be in the format 'ip:hostname' (e.g.,
    '10.119.6.8:MYMACHINE' )
    :param settings:
    :param session:
    :param claimipstring:
    :param capsv: custom attributes pipe separated values (see --help)
    :return:
    """
    logging.debug('------- ENTERING FUNCTION: claim_address() -------')
    url_addresses = str(settings.url_app) + '/addresses/'
    logging.debug(url_addresses)
    headers = {'app_id': str(settings.app),
               'Content-Type': 'application/json',
               'content': 'application/json',
               'token': str(session.token)  # calling token will auto-validate freshenss
               }
    '''
    Syntax for claiming IP via API:
    https://ipfreely.cardlytics.com/phpipam/api/piss/addresses/
    {
    "ip":"10.119.8.1",
    "subnetId":"30"
    }

    '''
    # create an address object then guess subnet
    try:
        logging.debug("capsv = " + str(capsv))
        logging.debug("claimipstring = " + str(claimipstring))
        # make sure we're looking at an IP
        claimip = claimipstring.split(':')[0]
        claimhost = claimipstring.split(':')[1]
        if session.hostname_validation:
            if not valid_hostname(claimhost):
                message = 'INVALID HOSTNAME: Hostname must be between 1 and 15 characters and not contain underscores.'
                print(message)
                logging.critical(message)
                sys.exit(1)
        int(claimip.split('.')[0])
        local_custom_attributes = []
        # process custom attributes and set up default values
        try:
            # first loop through and figure out what custom attrs we're supposed to know about
            for attr in session.custom_attributes:
                cattr = CustomAttribute()
                cattr.attribute_name = attr.attribute_name
                cattr.attribute_type = attr.attribute_type
                cattr.attribute_default_value = attr.attribute_default_value
                cattr.attribute_value = attr.attribute_default_value
                # now try to process the cajson parameter
                try:
                    lkv = capsv.split('|')
                    for kv in lkv:
                        a = kv.split(':')[0]
                        v = kv.split(':')[1]
                        logging.debug('capsv parsed attribute = ' + str(a))
                        logging.debug('capsv parsed value = ' + str(v))
                        if cattr.attribute_name == a:
                            cattr.attribute_value = v
                except Exception as arn:
                    mess = "Exception processing provided capsv: " + str(arn)
                    logging.debug(mess)
                local_custom_attributes.append(cattr)
        except Exception as orn:
            message = "Exception processing custom attributes in CLAIMIP: " + str(orn)
            logging.debug(message)
        s_addr = Address(local_custom_attributes)
        s_addr.ip = claimip
        s_addr.subnetId = imports.find_subnet_id(session, s_addr.guess_subnet())
        s_addr.hostname = claimhost
        s_addr.process_short_name()  # try to get short name from an FQDN
        s_addr.convert_json()
        json_prop = json.dumps(s_addr.dict_props)
        logging.debug("Attempting to create ip: " + str(s_addr.ip))
        r = requests.post(url_addresses, headers=headers, data=json_prop, verify=False)
        message = r.content
        message += "\nClaimed address |%s| for hostname |%s|." % (s_addr.ip, s_addr.hostname_short)
        logging.info(message)
        print(message)
        if not r.json().get('success'):
            sys.exit(1)
    except Exception as e:
        message = "Exception: " + str(e)
        logging.error(message)
        print(message)
        sys.exit(1)


def modify_address(settings, session, modipstring, capsv):
    """
    Modifies the address and hostname given in 'claimipstring'
    which should be in the format 'ip:hostname' (e.g.,
    '10.119.6.8:MYMACHINE' )
    :param settings:
    :param session:
    :param modipstring:
    :param capsv: custom attribute pip separated value (see --help)
    :return:
    """
    logging.debug('------- ENTERING FUNCTION: modify_address() -------')
    url_addresses = str(settings.url_app) + '/addresses/'
    logging.debug(url_addresses)
    headers = {'app_id': str(settings.app),
               'Content-Type': 'application/json',
               'content': 'application/json',
               'token': str(session.token)  # calling token will auto-validate freshenss
               }
    '''
    Syntax for modifying IP via API:
    -XPATCH https://ipfreely.cardlytics.com/phpipam/api/piss/addresses/
    {
    "id":"3045",
    "hostname":"newhostname"
    }

    '''
    # create an address object then guess subnet
    try:
        logging.debug("capsv = " + str(capsv))
        logging.debug("claimipstring = " + str(modipstring))
        # make sure we're looking at an IP
        modip = modipstring.split(':')[0]
        modhost = modipstring.split(':')[1]
        if session.hostname_validation:
            if not valid_hostname(modhost):
                message = 'INVALID HOSTNAME: Hostname must be between 1 and 15 characters and not contain underscores.'
                print(message)
                logging.critical(message)
                sys.exit(1)
        int(modip.split('.')[0])
        # find the address object
        cattr = search_for_ip(session, modip)
        try:
            lkv = capsv.split('|')
            for kv in lkv:
                a = kv.split(':')[0]
                v = kv.split(':')[1]
                logging.debug('capsv parsed attribute = ' + str(a))
                logging.debug('capsv parsed value = ' + str(v))
                setattr(cattr, a, v)
        except Exception as arn:
            mess = "Exception processing provided capsv: " + str(arn)
            logging.debug(mess)
        cattr.hostname = modhost
        cattr.process_short_name()  # try to get short name from an FQDN
        cattr.convert_json()

        # for PATCH calls the IP and SUBNET must be stripped out or you get errors
        # because you're trying to "Change" the ip and subnet, dumb
        dict_props = cattr.dict_props
        dict_props.pop('ip')
        dict_props.pop('subnetId')
        json_prop = json.dumps(dict_props)

        logging.debug("Attempting to modify ip: " + str(cattr.ip))
        url_address = url_addresses + cattr.id + '/'
        logging.debug(str(json.dumps(json_prop)))
        r = requests.patch(url_address, headers=headers, data=json_prop, verify=False)
        message = r.content
        logging.info(message)
        print(message)
        if not r.json().get('success'):
            sys.exit(1)
    except Exception as e:
        message = "Exception: " + str(e)
        logging.error(message)
        print(message)
        sys.exit(1)


def release_address(settings, session, releaseipstring):
    """
    Releases the address and hostname given in 'releaseipstring'
    which should be in the format 'ip' (e.g.,
    '10.119.6.8' )
    :param settings:
    :param session:
    :param releaseipstring:
    :return:
    """
    logging.debug('------- ENTERING FUNCTION: release_address() -------')
    url_addresses = str(settings.url_app) + '/addresses/'
    url_search_base = str(url_addresses) + 'search/'
    logging.debug(url_addresses)
    headers = {'app_id': str(settings.app),
               'Content-Type': 'application/json',
               'content': 'application/json',
               'token': str(session.token)  # calling token will auto-validate freshenss
               }
    '''
    Syntax for deleting IP via API:
    -XGET http://api.phpipam.net/api/myAPP/addresses/search/10.10.10.1/
    -XDELETE http://api.phpipam.net/api/myAPP/addresses/1/

    '''
    # find the id of the address
    try:
        # lazy test to make sure we're looking at an IP
        int(releaseipstring.split('.')[0])
    except Exception as e:
        message = "Exception: " + str(e)
        logging.error(message)
        print(message)
        sys.exit(1)
    try:
        id_to_delete = ''
        url_search = url_search_base + releaseipstring + "/"
        r = requests.get(url_search, headers=headers, verify=False)
        logging.debug(r.content)
        if r.json().get('success'):
            if len(r.json().get('data')) > 1:
                message = "ERROR: More than one address found. "
                logging.error(message)
                print(message)
                sys.exit(1)
            for j_address in r.json().get('data'):
                id_to_delete = j_address.get('id')
                break
        logging.info('id_to_delete: ' + id_to_delete)
        url_delete = url_addresses + id_to_delete + "/"
        logging.debug("DELETE URL = " + url_delete)
        r = requests.delete(url_delete, headers=headers, verify=False)
        message = r.content
        logging.info(message)
        print(message)
        if not r.json().get('success'):
            sys.exit(1)
    except Exception as e:
        message = "Exception: " + str(e)
        logging.error(message)
        print(message)
        sys.exit(1)


def search_for_ip(session, ip):
    """
    searches all addresses in the current session for a specific ip
    returns string with hostname and ip. Returns the address object.
    :param session:
    :param ip:
    :return: found_addr
    """
    results = [x for x in session.addresses if x.ip == ip]
    message = ''
    found_addr = None
    for address in results:
        try:
            message += '[%s]\n' % address.hostname_short
            message += '%s\n' % address.ip
            found_addr = address
        except:
            pass
    if message == '':
        message += "HOSTNAME NOT FOUND"
    else:
        message += "FOUND"
    logging.info(message)
    return found_addr


def search_for_hostname(session, hostname, deadend=None):
    """
    searches all addresses in the current session for a specific hostname
    returns string with hostname and ip
    :param session:
    :param hostname:
    :param deadend: Boolean to flag whether or not to exit after completion
    :return: found: Boolean indicating whether or not the hostname was found
    """
    #
    if deadend is None:
        deadend = True
    results = [x for x in session.addresses if x.hostname_short.lower() == hostname.lower()]
    message = ''
    for address in results:
        try:
            message += '[%s]\n' % address.hostname_short
            message += '%s\n' % address.ip
        except:
            pass
    if message == '':
        found = False
        message += "HOSTNAME NOT FOUND"
    else:
        found = True
        message += "FOUND"
    logging.info(message)
    print(message)
    if deadend:
        if found:
            sys.exit(0)
        else:
            sys.exit(1)
    else:
        return found


def filter_addresses(session, apply_custom_filters=None):
    """
    Takes a session object and applies various filters from
    config and options and returns a filtered list of Address
    objects.
    :param session:
    :param apply_custom_filters: whether or not to filter based on custom_filters
    :return: filtered_addresses
    """
    logging.debug('------- ENTERING FUNCTION: filter_addresses() -------')
    if apply_custom_filters is None:
        apply_custom_filters = False
    filtered_addresses = []
    for address in session.addresses:
        if address.filter_included or apply_custom_filters is False:
            subnetstring = '.'.join(address.ip.split('.')[:3]) + '.0'
            if session.filter_subnet:
                if (
                        subnetstring not in session.ansible_ignore_subnets and
                        address.hostname_short not in session.ansible_ignore_hostnames and
                        subnetstring in session.filter_subnet):
                    filtered_addresses.append(address)
            else:
                if (
                        subnetstring not in session.ansible_ignore_subnets and
                        address.hostname_short not in session.ansible_ignore_hostnames):
                    filtered_addresses.append(address)
    logging.debug("Exiting filter_addresses with addresses length: '%s'" % str(len(filtered_addresses)))
    return filtered_addresses


def group_by_hostname(list_addresses):
    """
    Searches through addresses and adds metadata to each
    address.related_ids so we know that objects are linked.
    :param list_addresses:
    :return:
    """
    logging.debug('------- ENTERING FUNCTION: group_by_hostname() -------')
    # first grab all the hostnames and find out those which have duplicates
    hostnames = []
    hostnames_duplicated = []
    for address in list_addresses:
        hostnames.append(address.hostname_short)
    for item in list(set([x for x in hostnames if hostnames.count(x) > 1])):
        hostnames_duplicated.append(item)

    # now we have a list of those hostnames which have duplicates so we
    # go through and find out the address IDs for those hostnames
    count = 0
    for hostname in hostnames_duplicated:
        associated_ids = list([str(x.id) for x in list_addresses if x.hostname_short == hostname])
        # logging.debug(str(associated_ids))
        # now find address with this hostname and append those associated ids
        for address in list_addresses:
            if address.hostname_short == hostname:
                address.related_ids = associated_ids
                count += 1
    logging.debug("Made %s associated_ids modifications to addresses" % str(count))
    return list_addresses


def ansible_inventory_duplicates(list_addresses):
    """
    Looks at the list of Address objects and does some
    validation to make sure we don't spit out duplicate
    hostnames and hostname garbage.
    :param list_addresses:
    :return: isvalid
    """
    logging.debug('------- ENTERING FUNCTION: ansible_inventory_duplicates() -------')
    result_hostnames = True
    result_ips = True
    ips = []
    hostnames = []
    for address in list_addresses:
        ips.append(address.ip)
        hostnames.append(address.hostname_short)

    size_ips_original = len(ips)
    size_hostnames_original = len(hostnames)
    logging.debug('size_ips_original: ' + str(size_ips_original))
    logging.debug('size_hostnames_original: ' + str(size_hostnames_original))
    size_hostnames_deduped = len(set(hostnames))
    size_ips_deduped = len(set(ips))
    logging.debug('size_hostnames_deduped: ' + str(size_hostnames_deduped))
    logging.debug('size_ips_deduped: ' + str(size_ips_deduped))
    if size_hostnames_original > size_hostnames_deduped:
        logging.debug("ERROR: Duplicate hostnames in set detected: ")
        for item in list(set([x for x in hostnames if hostnames.count(x) > 1])):
            logging.debug('\t' + item)
        result_hostnames = False
    else:
        logging.debug("No duplicates detected for hostnames.")
    if size_ips_original > size_ips_deduped:
        logging.debug("ERROR: Duplicate IPs in set detected: ")
        for item in list(set([x for x in ips if ips.count(x) > 1])):
            logging.debug('\t' + item)
        result_ips = False
    else:
        logging.debug("No duplicates detected for IPs.")
    logging.debug("result_ips: '%s'" % str(result_ips))
    logging.debug("result_hostnames: '%s'" % str(result_hostnames))
    # return the boolean AND operation on the two results
    isvalid = result_hostnames and result_ips
    return isvalid


def delete_subnets(settings, session):
    """
    Deletes all subnets from the default_section
    :param settings:
    :param session:
    :return:
    """
    usermsg = ("Are you absolutely sure you want to delete all subnets and addresses in the " +
               "section '%s' (y/n): " % settings.default_section)
    logging.info(usermsg)
    decision = raw_input(usermsg)
    logging.info("Decision was: '%s'" % decision)
    if decision == 'y':
        logging.debug('------- ENTERING FUNCTION: delete_subnets() -------')
        url_subnets = '%s/subnets/' % str(settings.url_app)
        logging.debug('url_subnets: ' + url_subnets)
        headers = {'app_id': str(settings.app),
                   'Content-Type': 'application/json',
                   'content': 'application/json',
                   'token': str(session.token)  # calling token will auto-validate freshenss
                   }
        try:
            if len(session.subnets) >= 1:
                for subnet in session.subnets:
                    url_subnet = ('%s%s/' % (url_subnets, subnet.id))
                    requests.delete(url_subnet, headers=headers, verify=False)
            else:
                logging.info("No subnets loaded or no subnets to delete!")
            print("All subnets in section '%s' were deleted successfully." % settings.default_section)
        except Exception as ar:
            logging.critical("Exception: " + str(ar))
    else:
        sys.exit(0)


def first_available(settings, session, hoststring, capsv):
    """

    :param settings:
    :param session:
    :param hoststring:
    :param capsv:
    :return:
    """
    # general flow:
    #  INTERNAL: validate hostname string
    #  INTERNAL: get subnet id
    #  REST: get first available IP from that subnet id
    #  INTERNAL: Build claimIp request
    #  REST: claim IP
    logging.debug('------- ENTERING FUNCTION: first_available() -------')
    url_subnets = str(settings.url_app) + '/subnets/'
    logging.debug(url_subnets)
    headers = {'app_id': str(settings.app),
               'Content-Type': 'application/json',
               'content': 'application/json',
               'token': str(session.token)  # calling token will auto-validate freshenss
               }
    if session.hostname_validation:
        if not valid_hostname(hoststring):
            message = 'INVALID HOSTNAME: Hostname must be between 1 and 15 characters and not contain underscores.'
            print(message)
            logging.critical(message)
            sys.exit(1)
    if session.filter_subnet is None:
        message = ('ERROR DETERMINING SUBNET FOR FIRST AVAILABLE CLAIM: please specify subnet with the ' +
                   '"filter_subnet" config file setting or with the "--filtersubnet" CLI parameter. Exiting... ')
        print(message)
        logging.critical(message)
        sys.exit(1)
    try:
        subnetid = imports.find_subnet_id(session, session.filter_subnet)
        url_subnet = url_subnets + '/' + subnetid
        url_firstavailable = url_subnet + '/first_free/'
        r = requests.get(url_firstavailable, headers=headers, verify=False)
        logging.debug(r.content)
        if r.json().get('success'):
            ipstring = r.json().get('data')
        logging.debug("RETURNED IPSTRING = '%s'" % ipstring)
        claimipstring = ipstring + ':' + hoststring
        logging.debug("CONCAT IPSTRING AND HOSTSTRING = '%s'" % claimipstring)
        # now that we have our hostname and IP we can call the claim_ip function and let it handle the capsv
        claim_address(settings, session, claimipstring, capsv)
    except Exception as orr:
        message = 'Exception in first_available: ' + str(orr)
        print(message)
        logging.critical(message)
        sys.exit(1)


def valid_hostname(hoststring):
    """
    Validates proper hostnames being 0-15 chars and not containing underscores, etc.
    Thanks to Tim Pietzcker: http://stackoverflow.com/questions/2532053/validate-a-hostname-string
    :param hoststring: short name of the host
    :return: valid: Boolean indicating it's a proper hostname
    """
    import re
    if len(hoststring.split('.')[0]) > 15:
        return False
    if hoststring[-1] == ".":
        hoststring = hoststring[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hoststring.split("."))


def debug(settings, session, options):
    # logging.info(settings.dumpself())
    # logging.info(session.dumpself())
    logging.info('************************************************')
    count = 0
    message = ''
    for address in filter_addresses(session):
        message += ('\t\t' + address.dumpself_tableformat())
        count += 1
    logging.info(message)
    logging.info("Number of filtered results: " + str(count))
    logging.info(session.dump_stats())
    logging.info('************************************************')
    logging.info(session.dumpself())
    '''
    logging.info('===============================')
    validation_results = ansible_inventory_duplicates(session.addresses)
    logging.debug("Validation Results: " + str(validation_results))
    if validation_results == False:
        logging.info("ERROR: DUPES DETECTED")
    else:
        logging.info(session.dumpself_ansible_inventory(options.filtersubnet))
    logging.info('+++++++++++++++++++++++++++++++')
    '''


def dataload(opts):
    logging.debug('------- ENTERING FUNCTION: dataload() -------')
    settings = process_config(opts.configfile)
    # build a runtime object to store pulled data
    session = Runtime()
    # if filter_subnet came in from config process it first
    try:
        session.filter_subnet = settings.filter_subnet
    except Exception as arr:
        logging.debug("Exception processing filter_subnet from config file: " + str(arr))
    # command line option filter_subnet always trumps config file so overwrite
    if opts.filtersubnet:
        try:
            int(opts.filtersubnet.split('.')[2])
            session.filter_subnet = opts.filtersubnet
        except Exception as ar:
            logging.critical("Exception processing options.filtersubnet: " + str(ar))
    if opts.nohostnamevalidation:
        settings.hostname_validation = False
        session.hostname_validation = False
    # append custom attributes to Runtime
    if len(settings.custom_attributes) > 0:
        session.custom_attributes = settings.custom_attributes
    session.custom_filters = settings.custom_filters
    session.ansible_ignore_subnets = settings.ansible_ignore_subnets
    session.ansible_ignore_hostnames = settings.ansible_ignore_hostnames
    session = authenticate(settings, session)
    logging.info("Expired?: " + str(session.token.is_expired()))
    logging.info("Token = " + session.token.__repr__())
    logging.info("Expires = " + session.token.get_expiration())
    session = loaders.load_sections(settings, session)
    # create_section(settings,session)
    session = loaders.load_subnets(settings, session)
    session = loaders.load_addresses(settings, session, filter_subnet=opts.filtersubnet)
    session.addresses = group_by_hostname(filter_addresses(session))
    return settings, session


def main(opts):
    """ The main() method. Program starts here.
    :param opts:
    :return:
    """
    # dataload_test(options)
    logging.debug("Full path to config file: " + str(opts.configfile))
    (settings, session) = dataload(opts)

    if opts.list:
        dump_ansible(filter_addresses(session, apply_custom_filters=True))
        sys.exit(0)
    elif opts.firstavailable:
        first_available(settings, session, opts.firstavailable, opts.capsv)
        sys.exit(0)
    elif opts.claimip:
        claim_address(settings, session, opts.claimip, opts.capsv)
        sys.exit(0)
    elif opts.modifyip:
        modify_address(settings, session, opts.modifyip, opts.capsv)
        sys.exit(0)
    elif opts.releaseip:
        release_address(settings, session, opts.releaseip)
        sys.exit(0)
    elif opts.searchhostname:
        search_for_hostname(session, opts.searchhostname)
        sys.exit(0)
    else:
        if opts.deletesubnets:
            delete_subnets(settings, session)

        (settings, session) = dataload(opts)
        if opts.subnetfile:
            imports.import_subnets(settings, session, opts)

        (settings, session) = dataload(opts)
        if opts.addressfile:
            imports.import_addresses(settings, session, opts)

        debug(settings, session, opts)


if __name__ == '__main__':
    """
    This main section is mostly for parsing arguments to the
    script and setting up debugging
    """

    from optparse import OptionParser
    # set up an additional option group just for debugging parameters
    from optparse import OptionGroup

    usage = "%prog [--debug] [--printtostdout] [--logfile] [--version] [--help] [--samplefileoption]"
    usage += '\nInteracts with the phpIpam API as defined in the config file INI. Calling with no options\n'
    usage += ' will simply load data from the system.'
    # set up the parser object
    parser = OptionParser(usage, version='%prog ' + sversion)
    parser.add_option('-c', '--configfile',
                      type='string',
                      metavar='FILE',
                      help="REQUIRED: config ini file. See sample. (default = 'runningconfig.ini'",
                      default='runningconfig.ini')
    parser.add_option('--filtersubnet',
                      type='string',
                      help="When loading addresses limit load to a single subnet e.g., '10.119.6.0'. This flag " +
                           "overrides the 'filter_subnet' setting within the config file. (Default: None)",
                      default=None)
    parser.add_option('--searchhostname',
                      type='string',
                      help=("Searches inventory for given hostname  e.g., 'MYMACHINE'. NOTE: filters still apply" +
                            " first  (Default: None)"),
                      default=None)
    parser.add_option('--subnetfile',
                      type='string',
                      metavar='FILE',
                      help="CSV File from which to import new subnets into the default section. (Default: None)",
                      default=None)
    parser.add_option('--addressfile',
                      type='string',
                      metavar='FILE',
                      help="CSV File from which to import new addresses into the default section. (Default: None)",
                      default=None)
    parser.add_option('--deletesubnets',
                      action='store_true',
                      help=("Boolean flag. If this option is present then all subnets in the default_section " +
                            "will be DELETED (default=False)"),
                      default=False)
    parser.add_option('--list',
                      action='store_true',
                      help=("Boolean flag. If this option is present then the Ansible formatted inventory will be " +
                            "be printed to stdout (default=False)"),
                      default=False)
    parser.add_option('--nohostnamevalidation',
                      action='store_true',
                      help=("Boolean flag. If this option is present then no hostname rule checking will be  " +
                            "performed (default=False)"),
                      default=False)
    parser.add_option('--claimip',
                      type='string',
                      help=("Claim IP and assign hostname. Syntax is ip:hostname. E.g., '10.119.6.145:MYMACHINE01. " +
                            "  (Default = None)"),
                      default=None)
    parser.add_option('--modifyip',
                      type='string',
                      help=("Modify IP and change hostname. Syntax is ip:hostname. E.g., '10.119.6.145:MYMACHINE01. " +
                            "  (Default = None)"),
                      default=None)
    parser.add_option('--capsv',
                      type='string',
                      help=("Custom attribute pipe separated string. Used primarily with --claimip and --modifyip." +
                            " Will attempt to set the keyvalue data given to match the custom attributes defined " +
                            "in the INI file. Example: 'cdl_isprod:0|cdl_autodelete:0|cdl_dhcp:1' (Default=None"),
                      default=None)
    parser.add_option('--releaseip',
                      type='string',
                      help=("Release IP delete all associated information including hostname and additional " +
                            "attributes. Syntax is 'ip'. E.g., '10.119.6.145' (Default=None)"),
                      default=None)
    parser.add_option('--firstavailable',
                      type='string',
                      help=("Searches for and claims the first available IP in a given subnet and sets the hostname " +
                            "and any additional custom attributes with the --capsv string. If no filter_subnet is " +
                            "specified via --filtersubnet or 'filter_subnet' in config file then this function will " +
                            "return an error. " +
                            "E.g. '--firstavailable MYHOSTNAME --capsv cdl_isprod:0|cdl_autodelete:0|cdl_dhcp:1' OR " +
                            " '--firstavailable MYHOSTNAME --filtersubnet 10.119.125.0' "
                            "(Default=None)"),
                      default=None)
    parser_debug = OptionGroup(parser, 'Debug Options')
    parser_debug.add_option('-d', '--debug', type='string',
                            help=('Available levels are CRITICAL (3), ERROR (2), '
                                  'WARNING (1), INFO (0), DEBUG (-1)'),
                            default='CRITICAL')
    parser_debug.add_option('-p', '--printtostdout', action='store_true',
                            default=False, help='Print all log messages to stdout')
    parser_debug.add_option('-l', '--logfile', type='string', metavar='FILE',
                            help=('Desired filename of log file output. Default '
                                  'is "' + defaultlogfilename + '"'),
                            default=defaultlogfilename)
    # officially adds the debugging option group
    parser.add_option_group(parser_debug)
    options, args = parser.parse_args()  # here's where the options get parsed

    try:  # now try and get the debugging options
        loglevel = getattr(logging, options.debug)
    except AttributeError:  # set the log level
        loglevel = {3: logging.CRITICAL,
                    2: logging.ERROR,
                    1: logging.WARNING,
                    0: logging.INFO,
                    -1: logging.DEBUG,
                    }[int(options.debug)]

    try:
        open(options.logfile, 'w')  # try and open the default log file
    except:
        print("Unable to open log file '%s' for writing." % options.logfile)
        logging.critical(
            "Unable to open log file '%s' for writing." % options.logfile)

    setuplogging(loglevel, options.printtostdout, options.logfile)
    try:
        if options.configfile == 'runningconfig.ini':
            # try to get the real directory of the running script
            currdir = os.path.dirname(os.path.realpath(__file__))
            options.configfile = currdir + "/" + "runningconfig.ini"
    except Exception as arrr:
        msg = "Exception processing config file location: " + str(arrr)
        logging.error(msg)
        print(msg)
        sys.exit(1)
    main(options)
