#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import collections
import jinja2
import jinja2.ext
import jinja2.sandbox
import json
import traceback

from ipalib import api
from ipalib import errors
from ipalib import Backend, Command
from ipalib import output
from ipalib.parameters import Dict, DNParam, Str, Principal
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.templating import IPAExtension
from .baseldap import (LDAPCreate, LDAPObject, LDAPRetrieve, LDAPSearch,
                       LDAPUpdate, LDAPDelete)
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
    parent_object = 'certprofile'

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

    permission_filter_objectclasses = ['ipacertfieldmappingrule']
    managed_permissions = {
        'System: Read Certificate Field Mappings': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn',
                'ipacertsyntaxmapping',
                'ipacertdatamapping',
                'objectclass',
            },
        },
        'System: Import Certificate Profile Mappings': {
            'ipapermright': {'add'},
            'default_privileges': {'CA Administrator'},
        },
        'System: Delete Certificate Profile Mappings': {
            'ipapermright': {'delete'},
            'default_privileges': {'CA Administrator'},
        },
    }


@register()
class certfieldmappingrule_add(LDAPCreate):
    NO_CLI = True

    __doc__ = _("""Create a new Cert Field Mapping Rule""")


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
        'cn', 'description', 'ipacertdataitem', 'ipacertdataprompt'
    ]
    search_attributes = [
        'cn', 'description', 'ipacertdataitem', 'ipacertdataprompt'
    ]
    label = _('Certificate Mapping Rules')
    label_singular = _('Certificate Mapping Rule')

    takes_params = (
        Str('cn',
            primary_key=True,
            cli_name='id',
            label=_('Certificate Mapping Rule ID'),
            doc=_('ID for referring to this mapping rule'),
        ),
        Str('description',
            cli_name='description',
            label=_('Description of this mapping rule'),
            doc=_('Description of this mapping rule'),
        ),
        Str('ipacertdataitem?',
            cli_name='var',
            label=_('Variable name referenced by this rule'),
            doc=_(
                'Variable name referenced by this rule. Required for data'
                ' rules. May be an expression if referring to something in the'
                ' database, but must be a single variable name if data will be'
                ' supplied by the user (--user-prompt is set).'),
        ),
        Str('ipacertdataprompt?',
            cli_name='user_prompt',
            label=_('Prompt to request this item from user'),
            doc=_('Prompt to request this item from user'),
        )
    )

    permission_filter_objectclasses = ['ipacertmappingruleset']
    managed_permissions = {
        'System: Read Certificate Mapping Rules': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn',
                'description',
                'objectclass',
            },
        },
        'System: Create Certificate Mapping Rules': {
            'ipapermright': {'add'},
            'default_privileges': {'CA Administrator'},
        },
        'System: Update Certificate Mapping Rules': {
            'ipapermright': {'write'},
            'default_privileges': {'CA Administrator'},
            'ipapermdefaultattr': {
                'cn',
                'description',
            },
        },
        'System: Delete Certificate Mapping Rules': {
            'ipapermright': {'delete'},
            'default_privileges': {'CA Administrator'},
        },
    }


@register()
class certmappingrule_add(LDAPCreate):
    __doc__ = _("""Create a new Certificate Mapping Rule""")


@register()
class certmappingrule_mod(LDAPUpdate):
    __doc__ = _("""Update a Certificate Mapping Rule""")


@register()
class certmappingrule_find(LDAPSearch):
    __doc__ = _("""Search for Certificate Mapping Rules""")


@register()
class certmappingrule_show(LDAPRetrieve):
    __doc__ = _("""Retrieve a Certificate Mapping Rule""")


@register()
class certmappingrule_del(LDAPDelete):
    __doc__ = _("""Delete a Certificate Mapping Rule""")


@register()
class certtransformationrule(LDAPObject):
    """
    Certificate Transformation rule object. Specifies a particular data
    transformation (comparable to a format string) that is used in converting
    stored data to certificate requests.
    """
    parent_object = 'certmappingrule'

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
            label=_('Certificate Transformation Rule ID'),
            doc=_('ID for referring to this transformation rule'),
        ),
        Str('ipacerttransformationtemplate',
            required=True,
            cli_name='template',
            label=_('String defining the transformation'),
            doc=_('String that specifies how the input data should be'
                  ' formatted and combined'),
        ),
        Str('ipacerttransformationhelper',
            required=True,
            multivalue=True,
            cli_name='helper',
            label=_('Name of CSR generation helper'),
            doc=_('Name of the CSR generation helper to which the syntax of'
                  ' this rule is targeted'),
        ),
    )

    permission_filter_objectclasses = ['ipacerttransformationrule']
    managed_permissions = {
        'System: Read Certificate Transformation Rules': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn',
                'ipacerttransformationtemplate',
                'ipacerttransformationhelper',
                'objectclass',
            },
        },
        'System: Create Certificate Transformation Rules': {
            'ipapermright': {'add'},
            'default_privileges': {'CA Administrator'},
        },
        'System: Update Certificate Transformation Rules': {
            'ipapermright': {'write'},
            'default_privileges': {'CA Administrator'},
            'ipapermdefaultattr': {
                'cn',
                'ipacerttransformationtemplate',
                'ipacerttransformationhelper',
            },
        },
        'System: Delete Certificate Transformation Rules': {
            'ipapermright': {'delete'},
            'default_privileges': {'CA Administrator'},
        },
    }


@register()
class certtransformationrule_add(LDAPCreate):
    __doc__ = _("""Create a new Certificate Transformation Rule""")


@register()
class certtransformationrule_mod(LDAPUpdate):
    __doc__ = _("""Update a Certificate Transformation Rule""")


@register()
class certtransformationrule_find(LDAPSearch):
    __doc__ = _("""Search for Certificate Transformation Rules""")


@register()
class certtransformationrule_show(LDAPRetrieve):
    __doc__ = _("""Retrieve a Certificate Transformation Rule""")


@register()
class certtransformationrule_del(LDAPDelete):
    __doc__ = _("""Delete a Certificate Transformation Rule""")


@register()
class cert_get_requestdata(Command):
    __doc__ = _('Gather data for a certificate signing request.')

    takes_options = (
        Principal('principal',
            label=_('Principal'),
            doc=_('Principal for this certificate (e.g.'
                  ' HTTP/test.example.com)'),
        ),
        Str('profile_id',
            validate_profile_id,
            label=_('Profile ID'),
            doc=_('Certificate Profile to use'),
        ),
        Str('helper',
            label=_('Name of CSR generation tool'),
            doc=_('Name of tool (e.g. openssl, certutil) that will be used to'
                  ' create CSR'),
        ),
        Str('out?',
            doc=_('Write CSR generation script to file'),
        ),
        Dict('userdata?',
             label=_('User-specified data items'),
             doc=_('Dict of user-specified data to include in the appropriate'
                   ' cert fields.'),
             flags=('no_option',),
        ),
    )

    has_output = (
        output.Output(
            'result',
            type=dict,
            doc=_('Dictionary mapping variable name to value'),
        ),
    )

    def execute(self, **kw):
        principal = kw.get('principal')
        profile_id = kw.get('profile_id')
        helper = kw.get('helper')
        userdata = kw.get('userdata', {})

        try:
            if principal.is_host:
                principal_obj = api.Command.host_show(
                    principal.hostname, all=True)
            elif principal.is_service:
                principal_obj = api.Command.service_show(
                    unicode(principal), all=True)
            elif principal.is_user:
                principal_obj = api.Command.user_show(
                    principal.username, all=True)
        except errors.NotFound:
            raise errors.NotFound(
                reason=_("The principal for this request doesn't exist."))
        principal_obj = principal_obj['result']

        request_data = self.Backend.certmapping.get_request_data(
            principal_obj, profile_id, helper, userdata)

        result = {}
        result.update(request_data)
        return dict(
            result=result
        )


@register()
class cert_get_userprompts(Command):
    __doc__ = _(
        'Report certificate signing request fields requiring user input.')

    takes_options = (
        Str('profile_id?',
            validate_profile_id,
            label=_('Profile ID'),
            doc=_('Certificate Profile to use. If not specified, uses the CA'
                  ' default.'),
        ),
        Str('helper',
            label=_('Name of CSR generation tool'),
            doc=_('Name of tool (e.g. openssl, certutil) that will be used to'
                  ' create CSR'),
        ),
    )

    has_output = (
        output.Output(
            'result',
            type=dict,
            doc=_('Dictionary mapping variable name to value'),
        ),
    )

    def execute(self, **kw):
        profile_id = kw.get('profile_id', self.Backend.ra.DEFAULT_PROFILE)
        helper = kw.get('helper')

        prompts = self.Backend.certmapping.get_user_prompts(
            profile_id, helper)

        return dict(
            result=prompts
        )


class IndexableUndefined(jinja2.Undefined):
    def __getitem__(self, key):
        return IndexableUndefined(
            hint=self._undefined_hint, obj=self._undefined_obj,
            name=self._undefined_name, exc=self._undefined_exception)


class Formatter(object):
    base_template_name = None

    def __init__(self, backend):
        self.backend = backend
        self.jinja2 = jinja2.sandbox.SandboxedEnvironment(
            loader=jinja2.FileSystemLoader('/usr/share/ipa/csrtemplates'),
            extensions=[jinja2.ext.ExprStmtExtension, IPAExtension],
            keep_trailing_newline=True, undefined=IndexableUndefined)

        self.passthrough_globals = {}
        self._define_passthrough('ipa.syntaxrule')
        self._define_passthrough('ipa.datarule')

    def _define_passthrough(self, call):

        def passthrough(caller):
            return u'{%% call %s() %%}%s{%% endcall %%}' % (call, caller())

        parts = call.split('.')
        current_level = self.passthrough_globals
        for part in parts[:-1]:
            if part not in current_level:
                current_level[part] = {}
            current_level = current_level[part]
        current_level[parts[-1]] = passthrough

    def build_template(self, rules):
        """
        Construct a template that can produce CSR generator strings.

        :param rules: list of MappingRuleset to use to populate the template.

        :returns: jinja2.Template that can be rendered to produce the CSR data.
        """
        syntax_rules = []
        for description, syntax_rule, data_rules in rules:
            data_rules_prepared = [
                self.prepare_data_rule(rule) for rule in data_rules]
            syntax_rules.append(self.prepare_syntax_rule(
                syntax_rule, data_rules_prepared, description))

        template_params = self.get_template_params(syntax_rules)
        base_template = self.jinja2.get_template(
            self.base_template_name, globals=self.passthrough_globals)

        try:
            combined_template_source = base_template.render(**template_params)
        except jinja2.UndefinedError:
            self.backend.debug(traceback.format_exc())
            raise errors.CertificateMappingError(reason=_(
                'Template error when formatting certificate data'))

        self.backend.debug(
            'Formatting with template: %s' % combined_template_source)
        combined_template = self.jinja2.from_string(combined_template_source)

        return combined_template

    def get_template_params(self, syntax_rules):
        raise NotImplementedError('Formatter class must be subclassed')

    def _wrap_rule(self, rule, rule_type):
        template = '{%% call ipa.%srule() %%}%s{%% endcall %%}' % (
            rule_type, rule)

        return template

    def _wrap_required(self, rule, name):
        template = '{%% filter required("%s") %%}%s{%% endfilter %%}' % (
            name, rule)

        return template

    def prepare_data_rule(self, data_rule):
        return self._wrap_rule(data_rule, 'data')

    def prepare_syntax_rule(self, syntax_rule, data_rules, name):
        self.backend.debug('Syntax rule template: %s' % syntax_rule)
        template = self.jinja2.from_string(
            syntax_rule, globals=self.passthrough_globals)
        try:
            is_required = getattr(template.module, 'required', False)
            rendered = template.render(datarules=data_rules)
        except jinja2.UndefinedError:
            self.debug(traceback.format_exc())
            raise errors.CertificateMappingError(reason=_(
                'Template error when formatting certificate data'))

        prepared_template = self._wrap_rule(rendered, 'syntax')
        if is_required:
            prepared_template = self._wrap_required(prepared_template, name)

        return prepared_template


class OpenSSLFormatter(Formatter):
    base_template_name = 'openssl_base.tmpl'
    SyntaxRule = collections.namedtuple(
        'SyntaxRule', ['template', 'is_extension'])

    def __init__(self, backend):
        super(OpenSSLFormatter, self).__init__(backend)
        self._define_passthrough('openssl.section')

    def get_template_params(self, syntax_rules):
        parameters = [rule.template for rule in syntax_rules
                      if not rule.is_extension]
        extensions = [rule.template for rule in syntax_rules
                      if rule.is_extension]

        return {'parameters': parameters, 'extensions': extensions}

    def prepare_syntax_rule(self, syntax_rule, data_rules, name):
        """Overrides method to pull out whether rule is an extension or not."""
        prepared_template = super(OpenSSLFormatter, self).prepare_syntax_rule(
            syntax_rule, data_rules, name)

        template = self.jinja2.from_string(
            syntax_rule, globals=self.passthrough_globals)
        try:
            is_extension = getattr(template.module, 'extension', False)
        except jinja2.UndefinedError:
            self.debug(traceback.format_exc())
            raise errors.CertificateMappingError(reason=_(
                'Template error when formatting certificate data'))

        return self.SyntaxRule(prepared_template, is_extension)


class CertutilFormatter(Formatter):
    base_template_name = 'certutil_base.tmpl'

    def get_template_params(self, syntax_rules):
        return {'options': syntax_rules}


FieldMapping = collections.namedtuple(
    'FieldMapping', [
        'description', 'syntax_rule', 'data_rules'])


@register()
class certmapping(Backend):
    FORMATTERS = {
        'openssl': OpenSSLFormatter,
        'certutil': CertutilFormatter,
    }

    def __fetch_rules(self, profile_id, helper):
        syntax_rules = []
        field_mappings = api.Command.certfieldmappingrule_find(
            profile_id)['result']
        field_mapping_templates = []
        for mapping in field_mappings:
            syntax_ruleset_name = mapping['ipacertsyntaxmapping'][0]['cn']
            syntax_ruleset = api.Command.certmappingrule_show(
                syntax_ruleset_name)['result']
            data_ruleset_dns = mapping['ipacertdatamapping']
            data_rulesets = [
                api.Command.certmappingrule_show(name['cn'])['result']
                for name in data_ruleset_dns]

            syntax_rule = self.get_rule_for_helper(syntax_ruleset, helper)
            data_rules = [self.get_rule_for_helper(ruleset, helper)
                          for ruleset in data_rulesets]
            field_mapping_templates.append(FieldMapping(
                syntax_ruleset_name, syntax_rule, data_rules))

        return field_mapping_templates

    def get_request_data(self, principal, profile_id, helper, userdata):
        config = api.Command.config_show()['result']
        render_data = {'subject': principal, 'config': config,
                       'userdata': userdata}

        formatter = self.FORMATTERS[helper](self)
        rules = self.__fetch_rules(profile_id, helper)
        template = formatter.build_template(rules)

        try:
            script = template.render(**render_data)
        except jinja2.UndefinedError:
            self.debug(traceback.format_exc())
            raise errors.CertificateMappingError(reason=_(
                'Template error when formatting certificate data'))

        return dict(script=script)

    def get_user_prompts(self, profile_id, helper):
        prompts = {}
        syntax_rules = []
        field_mappings = api.Command.certfieldmappingrule_find(
            profile_id)['result']
        for mapping in field_mappings:
            data_ruleset_names = mapping['ipacertdatamapping']
            for name in data_ruleset_names:
                ruleset = api.Command.certmappingrule_show(name['cn'])['result']
                if 'ipacertdataprompt' in ruleset:
                    try:
                        var = ruleset['ipacertdataitem'][0]
                    except KeyError:
                        raise errors.CertificateMappingError(reason=_(
                            'Certificate mapping rule %(rule)s has a prompt but'
                            ' no variable name set' % {'rule': name['cn']}))
                    if var in prompts:
                        raise errors.CertificateMappingError(reason=_(
                            'More than one data rule in this profile prompts'
                            ' for the %(item)s data item' % {'item': var}))

                    prompts[var] = ruleset['ipacertdataprompt'][0]

        return prompts

    def get_rule_for_helper(self, ruleset, helper):
        rules = api.Command.certtransformationrule_find(
            ruleset['cn'][0])['result']
        for rule in rules:
            if helper in rule['ipacerttransformationhelper']:
                template = rule['ipacerttransformationtemplate'][0]
                return template
        raise errors.NotFound(
            reason=_('No transformation in "%(ruleset)s" rule supports'
                     ' helper "%(helper)s"') %
            {'ruleset': ruleset['cn'][0], 'helper': helper})

    def get_profile_mappings(self, profile_id):
        """Return the list DNs for the certfieldmappingrules of a profile.

        If the profile does not exist, returns an empty list.
        """
        mappings = []
        try:
            rules = api.Command.certfieldmappingrule_find(
                profile_id)['result']
            mappings = [rule['dn'] for rule in rules]
        except (errors.NotFound, KeyError):
            pass

        return mappings

    def delete_profile_mappings(self, profile_id, mapping_dns):
        """Try to delete all the specified certfieldmappingrules.

        If one of the specified rules does not exist, continue on to the
        others.
        """
        for mapping in mapping_dns:
            try:
                api.Command.certfieldmappingrule_del(
                    profile_id, mapping['cn'])
            except errors.NotFound:
                pass

    def export_profile_mappings(self, profile_id):
        rules = []
        mappings = api.Command.certfieldmappingrule_find(
            profile_id)['result']
        for mapping in mappings:
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
        except ValueError:
            raise errors.ValidationError(
                name=_('mappings_file'), error=_('Not a valid JSON document'))

        return self.import_profile_mappings(profile_id, mappings)

    def import_profile_mappings(self, profile_id, mappings):
        # Validate user input
        if not isinstance(mappings, list):
            raise errors.ValidationError(
                name=_('mappings_file'), error=_('Must be a JSON array'))
        for mapping in mappings:
            if 'syntax' not in mapping:
                raise errors.ValidationError(
                    name=_('mappings_file'), error=_('Missing "syntax" key'))
            if 'data' not in mapping:
                raise errors.ValidationError(
                    name=_('mappings_file'), error=_('Missing "data" key'))
            if not isinstance(mapping['data'], list):
                raise errors.ValidationError(
                    name=_('mappings_file'),
                    error=_('"data" key must be an array'))

        old_maxindex = 0
        # Find the highest-numbered field rule named "field<integer>"
        for old_mapping in self.get_profile_mappings(profile_id):
            _empty, _field, index_str = old_mapping['cn'].rpartition('field')
            try:
                index = int(index_str)
            except ValueError:
                continue
            if index > old_maxindex:
                old_maxindex = index

        mapping_names = [u'field%s' % (old_maxindex + index + 1)
                         for index in range(len(mappings))]

        field_mappings = []
        try:
            for name, mapping in zip(mapping_names, mappings):
                syntax = self._get_dn(mapping['syntax'])
                data = [self._get_dn(rule) for rule in mapping['data']]
                field_mapping = api.Command.certfieldmappingrule_add(
                    profile_id, name, ipacertsyntaxmapping=syntax,
                    ipacertdatamapping=data)['result']
                field_mappings.append(field_mapping['dn'])
        except:
            self.delete_profile_mappings(profile_id, field_mappings)
            raise

        return field_mappings
