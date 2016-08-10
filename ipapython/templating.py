#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import pipes

from jinja2.ext import Extension

from ipalib import errors

class IPAExtension(Extension):
    """Jinja2 extension providing useful features for cert mapping rules."""

    def __init__(self, environment):
        super(IPAExtension, self).__init__(environment)

        environment.filters.update(
            quote=self.quote,
            safe_attr=self.safe_attr,
            missing=self.missing,
        )

    def quote(self, data):
        return pipes.quote(data)

    def safe_attr(self, obj, name):
        """Get an attribute of an object, ignoring exceptions.

        Works just like the attr() filter except that it returns undefined on
        more exceptions than just AttributeError when getting the attribute.
        """
        try:
            name = str(name)
        except UnicodeError:
            pass
        else:
            try:
                value = getattr(obj, name)
            except (AttributeError, ValueError):
                pass
            else:
                if (self.environment.sandboxed and not
                        self.environment.is_safe_attribute(obj, name, value)):
                    return self.environment.unsafe_undefined(obj, name)
                return value
        return self.environment.undefined(obj=obj, name=name)

    def missing(self, data):
        raise errors.CertificateMappingError(reason=_(
            'Required mapping rule is missing data'))
