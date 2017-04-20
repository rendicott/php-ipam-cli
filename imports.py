"""
This file holds the functions used to import addresses and
subnets from flat files for loading into the phpIpam db
via API.
"""

import logging
import csv
import json
import requests
from classes.Address import Address
from classes.Subnet import Subnet
from classes.CustomAttribute import CustomAttribute
from classes.CustomAttribute import CustomFilter
requests.packages.urllib3.disable_warnings()


def find_subnet_id(session, subnetstring):
    """
    Finds the subnet_id given the subnet string
    :param session:
    :param subnetstring:
    :return: subnet.id
    """
    for subnet in session.subnets:
        if subnetstring == subnet.subnet:
            return subnet.id


def import_subnets(settings, session, options):
    """
    Reads subnets from the options.subnetfile csv and creates
    them in the session.default_section_id.

    CSV is formatted as a single column file
    e.g.:
    subnet
    10.119.6.0/24
    192.168.1.0/24
    :param settings:
    :param session:
    :param options:
    :return: None
    """
    logging.debug('------- ENTERING FUNCTION: import_subnets() -------')
    url_subnets = settings.url_app + '/subnets/'
    logging.debug(url_subnets)
    headers = {'app_id': str(settings.app),
               'Content-Type': 'application/json',
               'content': 'application/json',
               'token': str(session.token)  # calling token will auto-validate freshness
               }
    with open(options.subnetfile, 'rb') as csvfile:
        f = csv.reader(csvfile, delimiter=',')
        for line in f:
            try:
                # make sure we're looking at an IP
                int(line[0].split('.')[0])
                subnet_with_mask = line[0]
                s_subnet = Subnet(subnet_with_mask)
                s_subnet.sectionId = session.default_section_id
                s_subnet.convert_json()
                json_prop = json.dumps(s_subnet.dict_props)
                r = requests.post(url_subnets, headers=headers, data=json_prop, verify=False)
                logging.debug(r.content)
            except Exception as e:
                logging.debug("Exception: " + str(e))


def import_addresses(settings, session, options):
    """
    Reads ip addresses from the options.subnetfile csv and creates them

    CSV is formatted as follows
    ip,name,metadata
    10.119.125.24,DEVADGITESQL01.CL.LOCAL,USED
    10.119.200.6,,AVAILABLE
    :param settings:
    :param session:
    :param options:
    :return: None
    """
    logging.debug('------- ENTERING FUNCTION: import_addresses() -------')
    url_addresses = settings.url_app + '/addresses/'
    logging.debug(url_addresses)
    headers = {'app_id': str(settings.app),
               'Content-Type': 'application/json',
               'content': 'application/json',
               'token': str(session.token)  # calling token will auto-validate freshenss
               }
    with open(options.addressfile, 'rb') as csvfile:
        f = csv.DictReader(csvfile)
        for i, line in enumerate(f):
            try:
                # make sure we're looking at an IP
                c_ip = line.get('Ip')
                int(c_ip.split('.')[0])
                c_status = line.get('Metadata')
                try:
                    c_description = line.get('Description')
                except:
                    c_description = ''
                try:
                    c_mac = line.get('mac')
                except:
                    c_mac = ''
                if c_status.lower() == 'used' or c_status.lower() == 'dhcp':
                    local_custom_attributes = list()
                    # process global custom attributes and set up default values for the object properties
                    # these are the custom attributes you could be looking for
                    try:
                        for attr in session.custom_attributes:
                            cattr = CustomAttribute()
                            cattr.attribute_name = attr.attribute_name
                            cattr.attribute_default_value = attr.attribute_default_value
                            cattr.attribute_value = attr.attribute_default_value
                            local_custom_attributes.append(cattr)
                    except Exception as orn:
                        message = "Exception processing custom attributes in IMPORTER: " + str(orn)
                        logging.debug(message)
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
                        msg = "Exception processing custom filters in IMPORTER: " + str(incp)
                        logging.debug(msg)
                    s_addr = Address(custom_attributes=local_custom_attributes, custom_filters=local_custom_filters)
                    s_addr.ip = c_ip
                    s_addr.subnetId = find_subnet_id(session, s_addr.guess_subnet())
                    if c_status.lower() == 'used':
                        c_hostname = line.get('Name')
                        if c_hostname is not '':
                            s_addr.hostname = c_hostname
                        if c_description is not '':
                            s_addr.description = c_description
                        if c_mac is not '':
                            s_addr.mac = c_mac
                        s_addr.process_short_name()  # try to get short name from an FQDN
                    elif c_status.lower() == 'dhcp':
                        s_addr.hostname = 'DHCP'
                        s_addr.description = 'DHCP'
                    # now try to pull custom attributes from CSV file and set them
                    # these are the actual values from the attributes you might be looking for
                    try:
                        for ca in s_addr.custom_attributes:
                            some_attr_val = line.get(ca.attribute_name)
                            setattr(s_addr, ca.attribute_name, some_attr_val)
                    except Exception as cep:
                        mssg = "Exception processing custom attribute from CSV IMPORT: " + str(cep)
                        logging.debug(mssg)
                    s_addr.convert_json()
                    json_prop = json.dumps(s_addr.dict_props)
                    logging.debug("Attempting to create ip: " + str(s_addr.ip))
                    # logging.debug(str(json_prop))
                    r = requests.post(url_addresses, headers=headers, data=json_prop, verify=False)
                    logging.debug(r.content)
                else:
                    continue
            except Exception as e:
                logging.debug("Exception: " + str(e))


if __name__ == '__main__':
    pass
