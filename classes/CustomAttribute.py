

class CustomAttribute:
    def __init__(self):
        self.attribute_name = None
        self.attribute_type = None
        self.attribute_default_value = None
        self.attribute_value = None

    def dumpself(self):
        msg = "ATTRIBUTE_NAME: " + str(self.attribute_name) + '\n'
        msg += "ATTRIBUTE_TYPE: " + str(self.attribute_type) + '\n'
        msg += "ATTRIBUTE_DEFAULT_VALUE: " + str(self.attribute_default_value) + '\n'
        msg += "ATTRIBUTE_VALUE: " + str(self.attribute_value) + '\n'
        msg += "------------------\n"
        return msg


class CustomFilter:
    def __init__(self):
        self.attribute_name = None
        self.attribute_desired_value = None

    def dumpself(self):
        msg = "ATTRIBUTE_FILTER: " + str(self.attribute_name) + '\n'
        msg += "\tATTRIBUTE_DESIRED_VALUE: " + str(self.attribute_desired_value) + '\n'
        return msg

    def matches_attribute(self, other):
        """
        Compares self value and attribute name to see if it matches a CustomAttribute
        :param other:
        :return:
        """
        rvalue = False
        if self.attribute_name == other.attribute_name:
            if self.attribute_desired_value == other.attribute_value:
                rvalue = True
        return rvalue
