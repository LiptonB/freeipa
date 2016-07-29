#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from ipaclient.frontend import CommandOverride, Str
from ipalib import util
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
        Str('script',
            label=_('Generation script'),
        ),
    )

    def forward(self, *keys, **options):
        if 'out' in options:
            util.check_writable_file(options['out'])

        profile_id = options.get('profile_id')
        format = options.get('format')
        prompts = self.api.Command.cert_get_userprompts(
            profile_id=profile_id, format=format)['result']

        userdata = {}
        for name, prompt in prompts.iteritems():
            userdata[name] = self.Backend.textui.prompt(prompt)

        cmd_options = options.copy()
        cmd_options['userdata'] = userdata

        result = super(cert_get_requestdata, self).forward(*keys, **cmd_options)

        if 'out' in options and 'script' in result['result']:
            with open(options['out'], 'wb') as f:
                f.write(result['result'].pop('script'))

        return result
