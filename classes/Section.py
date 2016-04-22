class Section():
    """
    Holds phpIpam section data loaded from API or
    this can be built and submitted to add sections
    via API.

    init: name
    """

    def __init__(self, name):
        self.id = None
        self.name = name
        self.description = None
        self.masterSection = '0'
        self.permissions = None
        self.strictMode = '1'
        self.subnetOrdering = 'default'
        self.order = None
        self.showVLAN = '1'
        self.showVRF = '1'
        self.DNS = None
        self.dict_props = {}

    def dumpself(self):
        fmt = '\t\t{0:20}{1}\n'
        msg = ''
        for attr in dir(self):
            if (
                    '__' not in attr and
                    'instancemethod' not in str(type(getattr(self, attr))) and
                    'dict' not in str(type(getattr(self, attr)))):
                msg += (fmt.format(attr, getattr(self, attr)))
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
                    'masterSection' not in attr):
                self.dict_props[attr] = getattr(self, attr)
