
import datetime


class Token:
    """
    Initialize with token string and expiry string.
    Sample Expiry String: '2016-04-07 06:22:43'
    methods:
      set_exp: converts expiry string to datetime
                and sets self.expires
      is_expired: returns true if token is expired
                  based on datetime.now()
      __repr__: returns string of token as long as
                token is not expired. Else returns
                'EXPIRED'
    """

    def __init__(self, token, expiry_string):
        self.dateFormat = '%Y-%m-%d %H:%M:%S'
        self.token = token
        self.expires = self.set_exp(expiry_string)

    def set_exp(self, expiry_string):
        """
        Takes the expiry string given by the phpIpam API
        and converts it to a datetime object so we can quickly
        check to see if the token is expired.
        :param expiry_string:
        :return:
        """
        rvalue = datetime.datetime.now()
        try:
            rvalue = datetime.datetime.strptime(
                    expiry_string,
                    self.dateFormat)
        except:
            pass
        return rvalue

    def is_expired(self):
        now = datetime.datetime.now()
        return self.expires < now

    def get_expiration(self):
        """
        Returns string formatted expiration date.
        """
        return self.expires.strftime(self.dateFormat)

    def __repr__(self):
        if not self.is_expired():
            return self.token
