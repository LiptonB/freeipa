#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import json
import pipes
import re

from ipalib import api
from ipalib import errors
from ipalib import Backend, DNParam, Str, Command
from ipalib import output
from ipalib.parameters import Principal
from ipalib.plugable import Registry
from ipalib.text import _
from .baseldap import (
    LDAPCreate, LDAPObject, LDAPRetrieve, LDAPSearch, LDAPUpdate, LDAPDelete)
from .certprofile import validate_profile_id

import six

if six.PY3:
    unicode = str

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
class certfieldmappingrule_del(LDAPDelete):
    NO_CLI = True

    __doc__ = _("""Delete a Cert Field Mapping Rule""")


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
class certmappingrule_del(LDAPDelete):
    NO_CLI = True

    __doc__ = _("""Delete a Certificate Mapping Rule""")

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
            multivalue=True,
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
class certtransformationrule_del(LDAPDelete):
    NO_CLI = True

    __doc__ = _("""Delete a Certificate Transformation Rule""")

@register()
class cert_get_requestdata(Command):
    __doc__ = _('Gather data for a certificate signing request.')

    takes_options = (
        Principal('principal',
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

        try:
            if principal.is_host:
                principal_obj = api.Command.host_show(principal.hostname, all=True)
            elif principal.is_service:
                principal_obj = api.Command.service_show(unicode(principal), all=True)
            elif principal.is_user:
                principal_obj = api.Command.user_show(principal.username, all=True)
        except errors.NotFound:
            raise errors.NotFound(
                reason=_("The principal for this request doesn't exist."))
        principal_obj = principal_obj['result']

        request_data = self.Backend.certmapping.get_request_data(principal_obj,
                profile_id, helper)

        result = {}
        result['debug_output'] = unicode(request_data)
        return dict(
            result=result
        )

class Formatter(object):
    def __format__(self, values):
        """
        Combine the values into a string for a particular CSR generator.

        :param values: list of unicode configuration statements

        :returns: unicode string presenting the configuration in a form
            suitable for input into the CSR generator.
        """
        raise NotImplementedError('Only subclasses of Formatter should be used')

class OpenSSLFormatter(Formatter):
    # TODO(blipton): What if we want a parenthesis in the section?
    SECTION_RE = re.compile(r'%section\((.*?)\)', re.DOTALL)
    EXTENSION_RE = re.compile(r'^ext:(.*)$', re.DOTALL+re.MULTILINE)

    def _parse_sections(self, value, sections):
        def process_section(match):
            sec_name = 'sec%s' % len(sections)
            sections.append(u'[%s]\n%s' % (sec_name, match.group(1)))
            return sec_name

        line = self.SECTION_RE.sub(process_section, value)
        return line

    def format(self, values):
        all_lines = [u'[req]', u'prompt = no']
        all_sections = []
        all_extensions = []
        for value in values:
            match = self.EXTENSION_RE.match(value)
            if match:
                value = match.group(1)

            line = self._parse_sections(value, all_sections)

            if match:
                all_extensions.append(line)
            else:
                all_lines.append(line)

        if all_extensions:
            all_lines.append(u'req_extensions = exts')
            exts = u'\n'.join([u'[exts]'] + all_extensions)
            all_sections.append(exts)

        main_section = u'\n'.join(all_lines)

        config = u'\n\n'.join([main_section] + all_sections)

        return config

class CertutilFormatter(Formatter):
    def format(self, values):
        return u'certutil -R %s' % u' '.join(values)

@register()
class certmapping(Backend):
    FORMATTERS = {
        'openssl': OpenSSLFormatter,
        'certutil': CertutilFormatter,
    }

    def get_request_data(self, principal, profile_id, helper):
        profile = api.Command.certprofile_show(profile_id, all=True)['result']

        command_args = {'principal': principal, 'profile_id': profile_id}

        field_values = []
        # TODO(blipton): Maybe we only want to store the CN since that's a
        # unique "id" field anyway
        field_mappings = [api.Command.certfieldmappingrule_show(mapping['cn'])['result']
                for mapping in profile['ipacertfieldmapping']]
        for mapping in field_mappings:
            syntax_ruleset_name = mapping['ipacertsyntaxmapping'][0]
            syntax_ruleset = api.Command.certmappingrule_show(syntax_ruleset_name['cn'])['result']
            data_ruleset_names = mapping['ipacertdatamapping']
            data_rulesets = [api.Command.certmappingrule_show(name['cn'])['result']
                    for name in data_ruleset_names]

            values = [self.evaluate_ruleset(ruleset, helper, **command_args) for ruleset in data_rulesets]
            real_values = [value for value in values if value is not None]
            if real_values:
                field_values.append(self.evaluate_ruleset(syntax_ruleset, helper, values=real_values, **command_args))

        formatter = self.FORMATTERS[helper]()
        formatted_values = formatter.format(field_values)
        return formatted_values

    def evaluate_ruleset(self, ruleset, helper, **kwargs):
        use_rule = None
        for rule_dn in ruleset['ipacerttransformation']:
            rule = api.Command.certtransformationrule_show(rule_dn['cn'])['result']
            if helper in rule['ipacerttransformationhelper']:
                use_rule = rule
                break
        if use_rule is None:
            raise errors.NotFound(
                    reason=_('No transformation in "%(ruleset)s" rule supports format "%(helper)s"')
                    % {'ruleset': ruleset['cn'][0], 'helper': helper})

        template = rule['ipacerttransformationtemplate'][0]
        if template.startswith('py:'):
            template = template[3:]
            template_method = getattr(self.Backend.datamapping, template)
            return template_method(kwargs)
        else:
            raise NotImplementedError('Only py rules allowed for now')

    def get_profile_mappings(self, profile_id):
        """Return the list of certfieldmappingrules in a profile.

        If the profile does not exist, returns an empty list.
        """
        mappings = []
        try:
            profile = api.Command.certprofile_show(profile_id, all=True)['result']
            mappings = profile['ipacertfieldmapping']
        except (errors.NotFound, KeyError):
            pass

        return mappings

    def delete_profile_mappings(self, mapping_dns):
        """Try to delete all the specified certfieldmappingrules.

        If one of the specified rules does not exist, continue on to the others.
        """
        for mapping in mapping_dns:
            try:
                api.Command.certfieldmappingrule_del(mapping['cn'])
            except errors.NotFound:
                pass

    def export_profile_mappings(self, profile_id):
        rules = []
        for mapping_dn in self.get_profile_mappings(profile_id):
            mapping = api.Command.certfieldmappingrule_show(mapping_dn['cn'])['result']
            syntax = mapping['ipacertsyntaxmapping'][0]['cn']
            data = [rule['cn'] for rule in mapping['ipacertdatamapping']]
            rules.append({'syntax': syntax, 'data': data})
        return rules

    def export_profile_mappings_json(self, profile_id):
        rules = self.export_profile_mappings(profile_id)
        return json.dumps(rules, indent=4) + '\n'

    def _get_dn(self, cn):
        mapping = api.Command.certmappingrule_show(cn)
        return mapping['result']['dn']

    def import_profile_mappings_json(self, profile_id, mappings_str):
        try:
            mappings = json.loads(mappings_str)
        except ValueError as err:
            raise errors.ValidationError(name=_('mappings_file'),
                    error=_('Not a valid JSON document'))

        return self.import_profile_mappings(profile_id, mappings)

    def import_profile_mappings(self, profile_id, mappings, mapping_names=None, old_mappings=None):
        self.debug('Backend.certmapping.import_profile_mappings(profile_id=%s,'
                'mappings=%s, mapping_names=%s, old_mappings=%s)' %
                (profile_id, mappings, mapping_names, old_mappings))
        # Validate user input
        if not isinstance(mappings, list):
            raise errors.ValidationError(name=_('mappings_file'),
                    error=_('Must be a JSON array'))
        for mapping in mappings:
            if 'syntax' not in mapping:
                raise errors.ValidationError(name=_('mappings_file'),
                        error=_('Missing "syntax" key'))
            if 'data' not in mapping:
                raise errors.ValidationError(name=_('mappings_file'),
                        error=_('Missing "data" key'))
            if not isinstance(mapping['data'], list):
                raise errors.ValidationError(name=_('mappings_file'),
                        error=_('"data" key must be an array'))

        if old_mappings is None:
            old_mappings = self.get_profile_mappings(profile_id)

        if mapping_names is None:
            old_maxindex = 0
            for mapping in old_mappings:
                _profile, _dash, index_str = mapping['cn'].rpartition('-')
                index = int(index_str)
                if index > old_maxindex:
                    old_maxindex = index

            mapping_names = ['%s-%s' % (profile_id, old_maxindex + index + 1)
                    for index in range(len(mappings))]

        field_mappings = []
        try:
            for name, mapping in zip(mapping_names, mappings):
                syntax = self._get_dn(mapping['syntax'])
                data = [self._get_dn(rule) for rule in mapping['data']]
                field_mapping = api.Command.certfieldmappingrule_add(name,
                        ipacertsyntaxmapping=syntax,
                        ipacertdatamapping=data)['result']
                field_mappings.append(field_mapping['dn'])
        except:
            self.delete_profile_mappings(field_mappings)
            raise

        self.delete_profile_mappings(old_mappings)

        return field_mappings


@register()
class datamapping(Backend):
    def _subject_base(self):
        config = api.Command['config_show']()['result']
        subject_base = config['ipacertificatesubjectbase'][0]
        return subject_base

    def syntaxSubjectOpenssl(self, extra_inputs):
        section = 'distinguished_name = %%section(%s)' % extra_inputs['values'][0]
        return section

    def dataHostOpenssl(self, extra_inputs):
        principal = extra_inputs['principal']
        if 'subject' in principal:
            subject = principal['subject']
        else:
            principal_name = principal['krbprincipalname'][0].hostname
            subject = u'CN=%s,%s' % (principal_name, self._subject_base())
        return subject.replace(u',', u'\n')

    def dataUsernameOpenssl(self, extra_inputs):
        principal = extra_inputs['principal']
        principal_name = principal['krbprincipalname'][0].username
        subject = u'CN=%s,%s' % (principal_name, self._subject_base())
        return subject.replace(u',', u'\n')

    def syntaxSubjectCertutil(self, extra_inputs):
        arg = '-s %s' % pipes.quote(extra_inputs['values'][0])
        return arg

    def dataHostCertutil(self, extra_inputs):
        principal = extra_inputs['principal']
        if 'subject' in principal:
            subject = principal['subject']
        else:
            principal_name = principal['krbprincipalname'][0].hostname
            subject = 'CN=%s,%s' % (principal_name, self._subject_base())
        return subject

    def dataUsernameCertutil(self, extra_inputs):
        principal = extra_inputs['principal']
        principal_name = principal['krbprincipalname'][0].username
        subject = u'CN=%s,%s' % (principal_name, self._subject_base())
        return subject

    def syntaxSANOpenssl(self, extra_inputs):
        section = 'ext:subjectAltName=@%%section(%s)' % '\n'.join(extra_inputs['values'])
        return section

    def syntaxSANCertutil(self, extra_inputs):
        san_list = ','.join(extra_inputs['values'])
        arg = '--extSAN %s' % pipes.quote(san_list)
        return arg

    def dataDNSOpenssl(self, extra_inputs):
        principal = extra_inputs['principal']
        principal_name = principal['krbprincipalname'][0].hostname
        return 'DNS=%s' % principal_name

    def dataDNSCertutil(self, extra_inputs):
        principal = extra_inputs['principal']
        principal_name = principal['krbprincipalname'][0].hostname
        return 'dns:%s' % principal_name

    def dataEmailOpenssl(self, extra_inputs):
        principal = extra_inputs['principal']
        if 'mail' in principal:
            return 'email=%s' % principal['mail'][0]
        else:
            return None

    def dataEmailCertutil(self, extra_inputs):
        principal = extra_inputs['principal']
        if 'mail' in principal:
            return 'email:%s' % principal['mail'][0]
        else:
            return None
