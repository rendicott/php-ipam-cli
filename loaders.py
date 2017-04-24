"""
This file holds the functions used to load addresses and
subnets from the phpIpam API.
"""

import logging
import requests

from classes.Address import Address
from classes.Subnet import Subnet
from classes.Section import Section
from classes.CustomAttribute import CustomAttribute
from classes.CustomAttribute import CustomFilter
requests.packages.urllib3.disable_warnings()


def load_addresses(settings, session, filter_subnet=None):
    """
    Loads all addresses from all loaded subnets.
    (i.e., only from the default_section)
    """
    logging.debug('------- ENTERING FUNCTION: load_addresses() -------')
    url_subnets = ('%s/subnets/' % settings.url_app)
    headers = {
                'app_id': str(settings.app),
                'Content-Type': 'application/json',
                'content': 'application/json',
                'token': str(session.token)  # calling token will auto-validate freshness
            }
    for subnet in session.subnets:
        if filter_subnet:
            if subnet.subnet != filter_subnet:
                continue
        url_subnet = ('%s%s/addresses/' % (url_subnets, subnet.id))
        r = requests.get(url_subnet, headers=headers, verify=False)
        if r.json().get('success'):
            for j_address in r.json().get('data'):
                s_id = j_address.get('id')
                s_subnetid = j_address.get('subnetId')
                s_ip = j_address.get('ip')
                s_is_gateway = j_address.get('is_gateway')
                s_description = j_address.get('description')
                s_hostname = j_address.get('hostname')
                s_mac = j_address.get('mac')
                s_owner = j_address.get('owner')
                s_tag = j_address.get('tag')
                s_deviceid = j_address.get('deviceId')
                s_port = j_address.get('port')
                s_note = j_address.get('note')
                s_lastseen = j_address.get('lastSeen')
                s_excludeping = j_address.get('excludePing')
                s_ptrignore = j_address.get('PTRIgnore')
                s_ptr = j_address.get('PTR')
                s_firewalladdressobject = j_address.get('firewallAddressObject')
                s_editdate = j_address.get('editDate')
                local_custom_attributes = []  # create a local instance so we can set values
                # logging.debug(str(r.content))
                try:
                    # pull custom_attributes if needed
                    if len(session.custom_attributes) > 0:
                        for attr in session.custom_attributes:
                            # create a new one first for local use and value setting
                            cattr = CustomAttribute()
                            cattr.attribute_name = attr.attribute_name
                            # logging.debug('cattr.attribute_name = ' + str(cattr.attribute_name))
                            cattr.attribute_type = attr.attribute_type
                            cattr.attribute_default_value = attr.attribute_default_value
                            cattr.attribute_value = j_address.get(cattr.attribute_name)
                            # logging.debug("cattr.attribute_value = " + str(cattr.attribute_value))
                            local_custom_attributes.append(cattr)
                except Exception as orn:
                    msg = "Exception processing custom attributes in loader: " + str(orn)
                    logging.debug(msg)
                local_custom_filters = list()
                try:
                    # pull in custom_filters if needed
                    if len(session.custom_filters) > 0:
                        for fltr in session.custom_filters:
                            cfilter = CustomFilter()
                            cfilter.attribute_name = fltr.attribute_name
                            cfilter.attribute_desired_value = fltr.attribute_desired_value
                            local_custom_filters.append(cfilter)
                except Exception as incp:
                    msg = "Exception processing custom filters in loader: " + str(incp)
                    logging.debug(msg)
                # do some filler if the hostname is junk
                if str(s_hostname) in ['???', 'None']:
                    s_hostname = session.generator.gimme_hostname()
                # now create Address object
                w_address = Address(custom_attributes=local_custom_attributes, custom_filters=local_custom_filters)
                # now set object properties
                w_address.id = s_id
                w_address.subnetId = s_subnetid
                w_address.ip = s_ip
                w_address.is_gateway = s_is_gateway
                w_address.description = s_description
                w_address.hostname = s_hostname
                # now that hostname is set we can try to determine short name
                w_address.process_short_name()
                w_address.mac = s_mac
                w_address.owner = s_owner
                w_address.tag = s_tag
                w_address.deviceId = s_deviceid
                w_address.port = s_port
                w_address.note = s_note
                w_address.lastSeen = s_lastseen
                w_address.excludePing = s_excludeping
                w_address.PTRignore = s_ptrignore
                w_address.PTR = s_ptr
                w_address.firewallAddressObject = s_firewalladdressobject
                w_address.editDate = s_editdate
                # now add address to session addresses
                session.addresses.append(w_address)
    return session


def load_subnets(settings, session):
    """
    Loads all subnets for the default_section
    :type session: object
    :type settings: object
    :param settings:
    :param session:
    :return: session
    """
    logging.debug('------- ENTERING FUNCTION: load_subnets() -------')
    url_subnets = ('%s/sections/%s/subnets/' % (settings.url_app, session.default_section_id))
    logging.debug('url_subnets: ' + url_subnets)
    headers = {'app_id': str(settings.app),
               'Content-Type': 'application/json',
               'content': 'application/json',
               'token': str(session.token)  # calling token will auto-validate freshness
               }
    r = requests.get(url_subnets, headers=headers, verify=False)
    try:
        if r.json().get('success'):
            for j_subnet in r.json().get('data'):
                # collect data from the returned content
                s_id = j_subnet.get('id')
                s_subnet = j_subnet.get('subnet')
                s_mask = j_subnet.get('mask')
                s_sectionid = j_subnet.get('sectionId')
                s_description = j_subnet.get('description')
                s_firewalladdressobject = j_subnet.get('firewallAddressObject')
                s_vrfid = j_subnet.get('vrfId')
                s_mastersubnetid = j_subnet.get('masterSubnetId')
                s_allowrequests = j_subnet.get('allowRequests')
                s_vlanid = j_subnet.get('vlanId')
                s_showname = j_subnet.get('showName')
                s_device = j_subnet.get('device')
                s_permissions = j_subnet.get('permissions')
                s_pingsubnet = j_subnet.get('pingSubnet')
                s_discoversubnet = j_subnet.get('discoverSubnet')
                s_dnsrecursive = j_subnet.get('DNSrecursive')
                s_dnsrecords = j_subnet.get('DNSrecords')
                s_nameserverid = j_subnet.get('nameserverId')
                s_scanagent = j_subnet.get('scanAgent')
                s_isfolder = j_subnet.get('isFolder')
                s_isfull = j_subnet.get('isFull')
                s_tag = j_subnet.get('tag')
                # now build the Subnet object
                w_subnet = Subnet(s_subnet)
                w_subnet.id = s_id
                w_subnet.subnet = s_subnet
                w_subnet.mask = s_mask
                w_subnet.sectionId = s_sectionid
                w_subnet.description = s_description
                w_subnet.firewallAddressObject = s_firewalladdressobject
                w_subnet.vrfId = s_vrfid
                w_subnet.masterSubnetId = s_mastersubnetid
                w_subnet.allowRequests = s_allowrequests
                w_subnet.vlanId = s_vlanid
                w_subnet.showName = s_showname
                w_subnet.device = s_device
                w_subnet.permissions = s_permissions
                w_subnet.pingSubnet = s_pingsubnet
                w_subnet.discoverSubnet = s_discoversubnet
                w_subnet.DNSrecursive = s_dnsrecursive
                w_subnet.DNSrecords = s_dnsrecords
                w_subnet.nameserverId = s_nameserverid
                w_subnet.scanAgent = s_scanagent
                w_subnet.isFolder = s_isfolder
                w_subnet.isFull = s_isfull
                w_subnet.tag = s_tag
                # append the subnet to the Runtime subnets
                session.subnets.append(w_subnet)
        else:
            logging.debug('ERROR')
    except Exception as e:
        logging.critical("Exception: " + str(e))
    return session


def load_sections(settings, session):
    """
    Reads sections from the phpIpam API and creates Section objects
    :param settings:
    :param session:
    :return: session
    """
    logging.debug('------- ENTERING FUNCTION: load_sections() -------')
    url_sections = settings.url_app + '/sections/'
    headers = {
                'app_id': str(settings.app),
                'Content-Type': 'application/json',
                'token': str(session.token)  # calling token will auto-validate freshenss
                }

    r = requests.get(url_sections, headers=headers, verify=False)
    if r.json().get('success'):
        for j_section in r.json().get('data'):
            s_id = j_section.get('id')
            s_name = j_section.get('name')
            s_description = j_section.get('description')
            s_mastersection = j_section.get('masterSection')
            s_permissions = j_section.get('permissions')
            s_strictmode = j_section.get('strictMode')
            s_subnetordering = j_section.get('subnetOrdering')
            s_order = j_section.get('order')
            s_showvlan = j_section.get('showVLAN')
            s_showvrf = j_section.get('showVRF')
            s_dns = j_section.get('DNS')
            # now build the Section object
            w_section = Section(s_name)
            w_section.id = s_id
            w_section.name = s_name
            w_section.description = s_description
            w_section.masterSection = s_mastersection
            w_section.permission = s_permissions
            w_section.strictMode = s_strictmode
            w_section.subnetOrdering = s_subnetordering
            w_section.order = s_order
            w_section.showVLAN = s_showvlan
            w_section.showVRF = s_showvrf
            w_section.DNS = s_dns
            # now add section to working session data
            session.sections.append(w_section)
        for section in session.sections:
            if section.name == settings.default_section:
                session.default_section_id = section.id
    else:
        logging.critical('ERROR')
    return session

if __name__ == '__main__':
    pass
