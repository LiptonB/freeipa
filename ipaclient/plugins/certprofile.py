#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipaclient.frontend import MethodOverride
from ipalib import util
from ipalib.parameters import File
from ipalib.plugable import Registry
from ipalib.text import _

import six

if six.PY3:
    unicode = str

register = Registry()


@register(override=True, no_fail=True)
class certprofile_show(MethodOverride):
    def forward(self, *keys, **options):
        if 'out' in options:
            util.check_writable_file(options['out'])
        if 'mappings_out' in options:
            util.check_writable_file(options['mappings_out'])

        result = super(certprofile_show, self).forward(*keys, **options)

        if 'out' in options and 'config' in result['result']:
            with open(options['out'], 'wb') as f:
                f.write(result['result'].pop('config'))
        if 'mappings_out' in options and 'mappings' in result['result']:
            with open(options['mappings_out'], 'wb') as f:
                f.write(result['result'].pop('mappings'))

        return result

    def output_for_cli(self, textui, output, *args, **options):
        rv = super(certprofile_show, self).output_for_cli(
                textui, output, *args, **options)

        if 'out' in options:
            textui.print_attribute(unicode(_('Profile configuration stored to')), options['out'])
        if 'mappings_out' in options:
            textui.print_attribute(unicode(_('Mapping rules stored to')), options['mappings_out'])


@register(override=True, no_fail=True)
class certprofile_import(MethodOverride):
    def get_options(self):
        for option in super(certprofile_import, self).get_options():
            if option.name in ['file', 'mappings_file']:
                option = option.clone_retype(option.name, File)
            yield option


@register(override=True, no_fail=True)
class certprofile_mod(MethodOverride):
    def get_options(self):
        for option in super(certprofile_mod, self).get_options():
            if option.name in ['file', 'mappings_file']:
                option = option.clone_retype(option.name, File)
            yield option
