
import logging
from TableFormat import TableFormat


class Address:
    """
    Holds phpIpam address data loaded from API or
    this can be built and submitted to add addresses
    via API.

    init: custom_attributes (required list of CustomAttribute objects)
    """
    def __init__(self, custom_attributes=None, custom_filters=None):
        if custom_attributes is None:
            custom_attributes = []
        if custom_filters is None:
            custom_filters = []
        self.id = None
        self.subnetId = None
        self.ip = None
        self.is_gateway = None
        self.description = None
        self.hostname = None
        self.hostname_short = None
        self.mac = None
        self.owner = None
        self.tag = None
        self.deviceId = None
        self.port = None
        self.note = None
        self.lastSeen = None
        self.excludePing = None
        self.PTRignore = None
        self.PTR = None
        self.firewallAddressObject = None
        self.editDate = None
        # now process the custom attributes if there are any
        self.process_custom_attributes(custom_attributes)
        # store the ones we know are custom for later in case we want to just reference custom attributes
        self.custom_attributes = custom_attributes
        self.custom_filters = custom_filters
        self.filter_included = True
        # now run through filters to see if we're included
        self.filter_included = self.include()
        self.related_ids = []  # holds additional Address object ids with the same hostname
        self.dict_props = {}
        self.dict_extend_values = {'ip': 15, 'mac': 15, 'owner': 15, 'id': 6, 'related_ids': 35, 'hostname': 30}
        self.dump_ignore_attrs = [
                                    'deviceId',
                                    'port',
                                    'lastSeen',
                                    'excludePing',
                                    'PTRignore',
                                    'PTR',
                                    'firewallAddressObject',
                                    'editDate']

    def dumpself(self):
        fmt = '\t\t{0:25}{1}\n'
        msg = ''
        for attr in dir(self):
            if (
                    '__' not in attr and
                    'instancemethod' not in str(type(getattr(self, attr)))):
                msg += (fmt.format(attr, getattr(self, attr)))
        return msg

    def process_custom_attributes(self, custom_attributes):
        for attr in custom_attributes:
            setattr(self, attr.attribute_name, attr.attribute_value)
            # logging.debug(attr.dumpself())

    def tableformat_header(self):
        msg = ''
        attributes = []
        values = []
        for attr in dir(self):
            if (
                    '__' not in attr and
                    'instancemethod' not in str(type(getattr(self, attr))) and
                    'dict' not in str(type(getattr(self, attr))) and
                    'dump_ignore_attrs' not in attr):
                attributes.append(attr)
                values.append(str(getattr(self, attr)))
        format_helper = TableFormat(attributes, values, self.dict_extend_values, self.dump_ignore_attrs)
        msg += format_helper.string_header
        return msg

    def include(self):
        """
        if one of the attributes in the custom filters has a match within custom attributes
        then this method will return True indicating this record should be included.
        :return:
        """
        rvalue = True
        negatives = 0
        for cfilter in self.custom_filters:
            try:
                val = getattr(self, cfilter.attribute_name)
                if not val == cfilter.attribute_desired_value:
                    negatives += 1
            except Exception as incp:
                message = "Exception looking up custom attribute value for custom filter: " + str(incp)
                logging.debug(message)
        if negatives > 0:
            rvalue = False
        return rvalue

    def dumpself_tableformat(self):
        msg = ''
        attributes = []
        values = []
        for attr in dir(self):
            if (
                    '__' not in attr and
                    'instancemethod' not in str(type(getattr(self, attr))) and
                    'dict' not in str(type(getattr(self, attr))) and
                    'dump_ignore_attrs' not in attr):
                attributes.append(attr)
                values.append(str(getattr(self, attr)))
        format_helper = TableFormat(attributes, values, self.dict_extend_values, self.dump_ignore_attrs)
        msg += format_helper.string_values
        return msg

    def convert_json(self):
        """
        Converts the properties/values of self to json to
        be used in POST bodies.
        :return: None
        """
        for attr in dir(self):
            if (
                    '__' not in attr and
                    'instancemethod' not in str(type(getattr(self, attr))) and
                    'dict' not in str(type(getattr(self, attr))) and
                    'masterSection' not in attr and
                    'deviceId' not in attr and
                    'dump_ignore_attrs' not in attr and
                    'editDate' not in attr and
                    'related_ids' not in attr and
                    'hostname_short' not in attr and
                    'custom_attributes' not in attr and
                    'custom_filters' not in attr and
                    'filter_included' not in attr):
                self.dict_props[attr] = getattr(self, attr)

    def guess_subnet(self):
        if self.ip is not None:
            return '.'.join(self.ip.split('.')[0:3]) + '.0'

    def dumpself_ansible_inventory_format(self):
        msg = ''
        msg += '[%s]\n' % self.hostname
        msg += '%s\n' % self.ip
        msg += '\n'
        return msg

    def process_short_name(self):
        try:
            self.hostname_short = self.hostname.split('.')[0]
        except:
            self.hostname_short = self.hostname
