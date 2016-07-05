#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from ipaclient.frontend import CommandOverride, Str
from ipalib.plugable import Registry
from ipalib.text import _

register = Registry()

import six

if six.PY3:
    unicode = str

__doc__ = _("""
Command override to display the produced CSR generation data
""")

@register(override=True, no_fail=True)
class cert_get_requestdata(CommandOverride):
    has_output_params = (
        Str('commandline',
            label=_('Command to run'),
        ),
        Str('configfile',
            label=_('Configuration file contents'),
        ),
    )
