
class UniqueGenerator:
    """
    Loaded into current Runtime session so that we can always
    grab a unique number for generating names from
    junk.
    """

    def __init__(self):
        self.counter = 1

    def gimme_int(self):
        msg = self.counter
        self.counter += 1
        return msg

    def gimme_string(self):
        msg = str(self.counter)
        self.counter += 1
        return msg

    def gimme_hostname(self):
        msg = ('UNKNOWN-%s' % str(self.counter))
        self.counter += 1
        return msg
