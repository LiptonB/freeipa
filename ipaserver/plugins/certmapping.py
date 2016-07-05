
from ipalib import api
from ipalib import DNParam, Str, Command
from ipalib import output
from ipalib.plugable import Registry
from ipalib.text import _
from .baseldap import (
    LDAPCreate, LDAPObject, LDAPRetrieve, LDAPSearch, LDAPUpdate)
from .certprofile import validate_profile_id


__doc__ = _("""
Mappings from FreeIPA data to Certificate Signing Requests.
""")

register = Registry()

@register()
class certfieldmappingrule(LDAPObject):
    """
    Certificate Field Mapping Rule object. Specifies how a particular cert
    field should be constructed within this profile.
    """
    container_dn = api.env.container_certfieldmappingrule
    object_name = _('Certificate Field Mapping Rule')
    object_name_plural = _('Certificate Field Mapping Rules')
    object_class = ['ipacertfieldmappingrule']
    default_attributes = [
        'cn', 'ipacertsyntaxmapping', 'ipacertdatamapping'
    ]
    search_attributes = [
        'cn', 'ipacertsyntaxmapping', 'ipacertdatamapping'
    ]
    label = _('Certificate Field Mapping Rules')
    label_singular = _('Certificate Field Mapping Rule')

    takes_params = (
        Str('cn',
            primary_key=True,
            cli_name='id',
            label=_('Field Mapping Rule ID'),
            doc=_('ID for referring to this field mapping rule'),
        ),
        DNParam('ipacertsyntaxmapping',
            required=True,
            cli_name='syntaxrule',
            label=_('Mapping ruleset for field syntax'),
            doc=_('Mapping ruleset for formatting entire field'),
        ),
        DNParam('ipacertdatamapping',
            required=True,
            multivalue=True,
            cli_name='datarule',
            label=_('Mapping ruleset for data items'),
            doc=_('Mapping ruleset for formatting individual items of data'),
        ),
    )

@register()
class certfieldmappingrule_add(LDAPCreate):
    NO_CLI = True

    __doc__ = _("""Create a new Cert Field Mapping Rule""")

@register()
class certfieldmappingrule_mod(LDAPUpdate):
    NO_CLI = True

    __doc__ = _("""Update a Cert Field Mapping Rule""")

@register()
class certfieldmappingrule_find(LDAPSearch):
    NO_CLI = True

    __doc__ = _("""Search for Cert Field Mapping Rules""")

@register()
class certfieldmappingrule_show(LDAPRetrieve):
    NO_CLI = True

    __doc__ = _("""Retrieve a Cert Field Mapping Rule""")


@register()
class certmappingrule(LDAPObject):
    """
    Certificate Mapping Rule object. Specifies how a particular cert
    field should be constructed within this profile.
    """
    container_dn = api.env.container_certmappingruleset
    object_name = _('Certificate Mapping Rule')
    object_name_plural = _('Certificate Mapping Rules')
    object_class = ['ipacertmappingruleset']
    default_attributes = [
        'cn', 'description', 'ipacerttransformation'
    ]
    search_attributes = [
        'cn', 'description', 'ipacerttransformation'
    ]
    label = _('Certificate Mapping Rules')
    label_singular = _('Certificate Mapping Rule')

    takes_params = (
        Str('cn',
            primary_key=True,
            cli_name='id',
            label=_('Field Mapping Rule ID'),
            doc=_('ID for referring to this mapping rule'),
        ),
        Str('description',
            required=True,
            cli_name='description',
            label=_('Description of this mapping rule'),
            doc=_('Description of this mapping rule'),
        ),
        DNParam('ipacerttransformation',
            required=True,
            multivalue=True,
            cli_name='datarule',
            label=_('Included transformation rule'),
            doc=_('Rule for formatting for a particular CSR generation tool'),
        ),
    )

@register()
class certmappingrule_add(LDAPCreate):
    NO_CLI = True

    __doc__ = _("""Create a new Certificate Mapping Rule""")

@register()
class certmappingrule_mod(LDAPUpdate):
    NO_CLI = True

    __doc__ = _("""Update a Certificate Mapping Rule""")

@register()
class certmappingrule_find(LDAPSearch):
    NO_CLI = True

    __doc__ = _("""Search for Certificate Mapping Rules""")

@register()
class certmappingrule_show(LDAPRetrieve):
    NO_CLI = True

    __doc__ = _("""Retrieve a Certificate Mapping Rule""")


@register()
class certtransformationrule(LDAPObject):
    """
    Certificate Transformation rule object. Specifies a particular data
    transformation (comparable to a format string) that is used in converting
    stored data to certificate requests.
    """
    container_dn = api.env.container_certtransformationrule
    object_name = _('Certificate Transformation Rule')
    object_name_plural = _('Certificate Transformation Rules')
    object_class = ['ipacerttransformationrule']
    default_attributes = [
        'cn', 'ipacerttransformationtemplate', 'ipacerttransformationhelper'
    ]
    search_attributes = [
        'cn', 'ipacerttransformationtemplate', 'ipacerttransformationhelper'
    ]
    label = _('Certificate Transformation Rules')
    label_singular = _('Certificate Transformation Rule')

    takes_params = (
        Str('cn',
            primary_key=True,
            cli_name='id',
            label=_('Field Mapping Rule ID'),
            doc=_('ID for referring to this transformation rule'),
        ),
        Str('ipacerttransformationtemplate',
            required=True,
            cli_name='template',
            label=_('String defining the transformation'),
            doc=_('String that specifies how the input data should be formatted and combined'),
        ),
        Str('ipacerttransformationhelper',
            required=True,
            cli_name='helper',
            label=_('Name of CSR generation helper'),
            doc=_('Name of the CSR generation helper to which the syntax of this rule is targeted'),
        ),
    )

@register()
class certtransformationrule_add(LDAPCreate):
    NO_CLI = True

    __doc__ = _("""Create a new Certificate Transformation Rule""")

@register()
class certtransformationrule_mod(LDAPUpdate):
    NO_CLI = True

    __doc__ = _("""Update a Certificate Transformation Rule""")

@register()
class certtransformationrule_find(LDAPSearch):
    NO_CLI = True

    __doc__ = _("""Search for Certificate Transformation Rules""")

@register()
class certtransformationrule_show(LDAPRetrieve):
    NO_CLI = True

    __doc__ = _("""Retrieve a Certificate Transformation Rule""")

@register()
class cert_get_requestdata(Command):
    __doc__ = _('Gather data for a certificate signing request.')

    takes_options = (
        Str('principal',
            label=_('Principal'),
            doc=_('Principal for this certificate (e.g. HTTP/test.example.com)'),
        ),
        Str('profile_id?', validate_profile_id,
            label=_('Profile ID'),
            doc=_('Certificate Profile to use'),
        ),
        Str('format',
            label=_('Name of CSR generation tool'),
            doc=_('Name of tool (e.g. openssl, certutil) that will be used to create CSR'),
        ),
    )

    has_output = (
        output.Output('result',
            type=dict,
            doc=_('Dictionary mapping variable name to value'),
        ),
    )

    def execute(self, **kw):
        principal = kw.get('principal')
        profile_id = kw.get('profile_id', self.Backend.ra.DEFAULT_PROFILE)
        helper = kw.get('format')

        result = {'debug_output': u'test'}
        return dict(
            result=result
        )
