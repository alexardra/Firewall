class Domainname(object):
    def __init__(self, domain):
        self._domain = domain

    def is_match(self, domainname):
        domainname = domainname.strip('/')
        try:
            suffix = self._domain[self._domain.index('*') + 1:]
            return domainname.endswith(suffix)
        except:
            return domainname == self._domain
