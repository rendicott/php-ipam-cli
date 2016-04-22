
from classes.UniqueGenerator import UniqueGenerator


class Runtime:
    """
    Holds application data loaded at runtime.
    """

    def __init__(self):
        self.token = None
        self.default_section_id = ''
        self.sections = []  # list of Section objects
        self.subnets = []  # list of Subnet objects
        self.addresses = []  # list of Address objects
        self.generator = UniqueGenerator()
        self.ansible_ignore_subnets = []
        self.ansible_ignore_hostnames = []
        self.custom_attributes = []
        self.custom_filters = []
        self.filter_subnet = None
        self.hostname_validation = True

    def dumpself_ansible_inventory(self, desired_subnet=None):
        working_subnet_id = ''
        msg = '\n'
        if desired_subnet is not None:
            for sub in self.subnets:
                if sub.subnet != desired_subnet:
                    working_subnet_id = sub.id
                    break
            for address in self.addresses:
                if address.subnetId == working_subnet_id:
                    msg += address.dumpself_ansible_inventory_format()
        else:
            for address in self.addresses:
                msg += address.dumpself_ansible_inventory_format()
        return msg

    def dumpself(self):
        fmt = '\t{0:20}{1}\n'
        msg = 'SESSION:\n'
        for attr in dir(self):
            if (
                    '__' not in attr and
                    'instancemethod' not in str(type(getattr(self, attr))) and
                    'list' not in str(type(getattr(self, attr)))):
                msg += (fmt.format(attr, getattr(self, attr)))
        for section in self.sections:
            msg += "\tSECTION:\n"
            msg += section.dumpself()
        msg += "\tSUBNETS:\n"
        try:
            msg += '\t\t' + self.subnets[0].tableformat_header()
        except Exception as ar:
            msg += "\t\tERROR: " + str(ar)
        for subnet in self.subnets:
            msg += '\t\t' + subnet.dumpself_tableformat()
        try:
            msg += "\tADDRESSES:\n"
            try:
                msg += '\t\t' + self.addresses[0].tableformat_header()
            except Exception as ar:
                msg += "\t\tERROR: " + str(ar)
        except Exception as e:
            print("Exception: " + str(e))
            msg += "\t\t\t\tNO ADDRESSES\n"
        for address in self.addresses:
            msg += '\t\t' + address.dumpself_tableformat()
        return msg

    def dump_stats(self):
        fmt = '\t\t{0:15}{1:15}\n'
        msg = ''
        msg += fmt.format('METRIC', 'COUNT')
        msg += '\t\t--------------------------\n'
        msg += fmt.format('subnets', str(len(self.subnets)))
        msg += fmt.format('addresses', str(len(self.addresses)))
        msg += fmt.format('uniquer_iter', str(self.generator.counter))
        msg += fmt.format('cstm_attrs', str(len(self.custom_attributes)))
        msg += fmt.format('cstm_fltrs', str(len(self.custom_filters)))
        return (msg)
