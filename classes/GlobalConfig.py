class GlobalConfig:
    """
    Holds configuration settings and
    common methods.
    """

    def __init__(self, base_url, app, username, password):
        self.base_url = base_url
        # this is the application you have to set up in the phpIpam API section in the web gui
        # since we're using HTTPS we have to always include the app_id in the header
        self.app = app
        self.url_app = self.check_url_format()
        self.url_user = self.url_app + 'user/'
        self.username = username
        self.password = password
        self.default_section = ''
        self.ansible_ignore_subnets = []
        self.ansible_ignore_hostnames = []
        self.custom_attributes = []
        self.custom_filters = []
        self.filter_subnet = None
        self.hostname_validation = True

    def dumpself(self):
        fmt = '\t{0:20}{1}\n'
        msg = '\nSETTINGS:\n'
        for attr in dir(self):
            if (
                    '__' not in attr and
                    'instancemethod' not in str(type(getattr(self, attr)))):
                msg += (fmt.format(attr, getattr(self, attr)))
        return msg

    def check_url_format(self):
        # handles building url regardless of trailing slash
        ub = self.base_url.strip('/')
        app = self.app.replace('/', '')
        final = ('%s/%s/' % (ub, app))
        return final
