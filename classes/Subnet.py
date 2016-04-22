from TableFormat import TableFormat


class Subnet:
    """
    Holds phpIpam subnet data loaded from API or
    this can be built and submitted to add subnets
    via API.

    init: subnet (required in CIDR format)
    """

    def __init__(self, subnet):
        self.id = None
        self.subnet = None
        self.mask = None
        self.parse_mask(subnet)
        self.sectionId = None
        self.description = None
        self.firewallAddressObject = None
        self.vrfId = None
        self.masterSubnetId = None
        self.vlanId = None
        self.showName = '0'
        self.device = '0'
        self.pingSubnet = '0'
        self.discoverSubnet = '0'
        self.DNSrecursive = '0'
        self.DNSrecords = '0'
        self.nameserverId = '0'
        self.scanAgent = '0'
        self.isFolder = '0'
        self.isFull = '0'
        self.dict_props = {}
        # Use dict_extend_values to size tableformat columns appropriately
        self.dict_extend_values = {'subnet': 15, 'id': 4}
        # Use dump_ignore_attrs to filter out unwanted attributes in tableformat dumps
        self.dump_ignore_attrs = ['DNSrecursive',
                                  'DNSrecords',
                                  'allowRequests',
                                  'device',
                                  'discoverSubnet',
                                  'firewallAddressObject',
                                  'pingSubnet',
                                  'nameserverId',
                                  'scanAgent',
                                  'showName',
                                  'vrfId',
                                  'masterSubnetId']

    def dumpself(self):
        fmt = '\t\t{0:25}{1}\n'
        msg = ''
        for attr in dir(self):
            if (
                    '__' not in attr and
                    'instancemethod' not in str(type(getattr(self, attr)))):
                msg += (fmt.format(attr, getattr(self, attr)))
        return msg

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
                # msg += (fmt.format(attr,getattr(self,attr)))
        format_helper = TableFormat(attributes, values, self.dict_extend_values, self.dump_ignore_attrs)
        msg += format_helper.string_header
        return msg

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
                # msg += (fmt.format(attr,getattr(self,attr)))
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
                    'dump_ignore_attrs' not in attr):
                self.dict_props[attr] = getattr(self, attr)

    def parse_mask(self, stringer):
        """
        Called to handle the instantiation when subnet is passed in as a CIDR formatted IP (e.g., 10.1.1.0/24)
        :param stringer:
        :return:
        """
        split_subnet = stringer.split('/')
        self.subnet = split_subnet[0]
        try:
            self.mask = split_subnet[1]
        except:
            # default to 24
            self.mask = '24'
