# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import collections
import xml.dom.minidom

import nss.nss as nss
import six
from six.moves.urllib.parse import urlencode

from ipalib import api, errors
from ipalib.errors import NetworkError
from ipalib.text import _
from ipapython import nsslib, ipautil
from ipapython.ipa_log_manager import root_logger

# Python 3 rename. The package is available in "six.moves.http_client", but
# pylint cannot handle classes from that alias
try:
    import httplib
except ImportError:
    import http.client as httplib

if six.PY3:
    unicode = str

Profile = collections.namedtuple('Profile', ['profile_id', 'description', 'store_issued', 'field_mappings'])
FieldMapping = collections.namedtuple('FieldMapping', ['id', 'syntax_mapping', 'data_mappings'])
MappingRuleset = collections.namedtuple('MappingRuleset', ['id', 'description', 'transformations'])
TransformationRule = collections.namedtuple('TransformationRule', ['id', 'template', 'helpers'])

INCLUDED_PROFILES = (
    Profile(u'caIPAserviceCert', u'Standard profile for network services', True,
        [u'hostSubject', u'DNSSAN']),
    Profile(u'IECUserRoles', u'User profile that includes IECUserRoles extension from request', True, []),
)

INCLUDED_FIELD_MAPPINGS = (
    FieldMapping(u'hostSubject', u'syntaxSubject', [u'dataHostCN']),
    FieldMapping(u'DNSSAN', u'syntaxSAN', [u'dataDNS']),
)

INCLUDED_MAPPING_RULESETS = (
    MappingRuleset(u'syntaxSubject', u'Syntax for adding a Subject Distinguished Name',
        [u'syntaxSubjectOpenssl', u'syntaxSubjectCertutil']),
    MappingRuleset(u'dataHostCN', u'DN with the principal\'s hostname as the CommonName',
        [u'dataHostOpenssl', u'dataHostCertutil']),
    MappingRuleset(u'syntaxSAN', u'Syntax for adding a Subject Alternate Name',
        [u'syntaxSANOpenssl', u'syntaxSANCertutil']),
    MappingRuleset(u'dataDNS',
        u'Constructs a SubjectAltName entry from the principal\'s hostname',
        [u'dataDNSOpenssl', u'dataDNSCertutil']),
)

INCLUDED_TRANSFORMATION_RULES = (
    TransformationRule(u'syntaxSubjectOpenssl', u'py:syntaxSubjectOpenssl', [u'openssl']),
    TransformationRule(u'syntaxSubjectCertutil', u'py:syntaxSubjectCertutil', [u'certutil']),
    TransformationRule(u'dataHostOpenssl', u'py:dataHostOpenssl', [u'openssl']),
    TransformationRule(u'dataHostCertutil', u'py:dataHostCertutil', [u'certutil']),
    TransformationRule(u'syntaxSANOpenssl', u'py:syntaxSANOpenssl', [u'openssl']),
    TransformationRule(u'syntaxSANCertutil', u'py:syntaxSANCertutil', [u'certutil']),
    TransformationRule(u'dataDNSOpenssl', u'py:dataDNSOpenssl', [u'openssl']),
    TransformationRule(u'dataDNSCertutil', u'py:dataDNSCertutil', [u'certutil']),
)


DEFAULT_PROFILE = u'caIPAserviceCert'


def error_from_xml(doc, message_template):
    try:
        item_node = doc.getElementsByTagName("Error")
        reason = item_node[0].childNodes[0].data
        return errors.RemoteRetrieveError(reason=reason)
    except Exception as e:
        return errors.RemoteRetrieveError(reason=message_template % e)


def get_ca_certchain(ca_host=None):
    """
    Retrieve the CA Certificate chain from the configured Dogtag server.
    """
    if ca_host is None:
        ca_host = api.env.ca_host
    chain = None
    conn = httplib.HTTPConnection(
        ca_host,
        api.env.ca_install_port or 8080)
    conn.request("GET", "/ca/ee/ca/getCertChain")
    res = conn.getresponse()
    doc = None
    if res.status == 200:
        data = res.read()
        conn.close()
        try:
            doc = xml.dom.minidom.parseString(data)
            try:
                item_node = doc.getElementsByTagName("ChainBase64")
                chain = item_node[0].childNodes[0].data
            except IndexError:
                raise error_from_xml(
                    doc, _("Retrieving CA cert chain failed: %s"))
        finally:
            if doc:
                doc.unlink()
    else:
        raise errors.RemoteRetrieveError(
            reason=_("request failed with HTTP status %d") % res.status)

    return chain


def _parse_ca_status(body):
    doc = xml.dom.minidom.parseString(body)
    try:
        item_node = doc.getElementsByTagName("XMLResponse")[0]
        item_node = item_node.getElementsByTagName("Status")[0]
        return item_node.childNodes[0].data
    except IndexError:
        raise error_from_xml(doc, _("Retrieving CA status failed: %s"))


def ca_status(ca_host=None):
    """Return the status of the CA, and the httpd proxy in front of it

    The returned status can be:
    - running
    - starting
    - Service Temporarily Unavailable
    """
    if ca_host is None:
        ca_host = api.env.ca_host
    status, headers, body = http_request(
        ca_host, 8080, '/ca/admin/ca/getStatus')
    if status == 503:
        # Service temporarily unavailable
        return status
    elif status != 200:
        raise errors.RemoteRetrieveError(
            reason=_("Retrieving CA status failed with status %d") % status)
    return _parse_ca_status(body)


def https_request(host, port, url, secdir, password, nickname,
        method='POST', headers=None, body=None, **kw):
    """
    :param method: HTTP request method (defalut: 'POST')
    :param url: The path (not complete URL!) to post to.
    :param body: The request body (encodes kw if None)
    :param kw:  Keyword arguments to encode into POST body.
    :return:   (http_status, http_headers, http_body)
               as (integer, dict, str)

    Perform a client authenticated HTTPS request
    """

    def connection_factory(host, port):
        no_init = secdir == nsslib.current_dbdir
        conn = nsslib.NSSConnection(host, port, dbdir=secdir, no_init=no_init,
                                    tls_version_min=api.env.tls_version_min,
                                    tls_version_max=api.env.tls_version_max)
        conn.set_debuglevel(0)
        conn.connect()
        conn.sock.set_client_auth_data_callback(
            nsslib.client_auth_data_callback,
            nickname, password, nss.get_default_certdb())
        return conn

    if body is None:
        body = urlencode(kw)
    return _httplib_request(
        'https', host, port, url, connection_factory, body,
        method=method, headers=headers)


def http_request(host, port, url, **kw):
    """
    :param url: The path (not complete URL!) to post to.
    :param kw: Keyword arguments to encode into POST body.
    :return:   (http_status, http_headers, http_body)
                as (integer, dict, str)

    Perform an HTTP request.
    """
    body = urlencode(kw)
    return _httplib_request(
        'http', host, port, url, httplib.HTTPConnection, body)


def _httplib_request(
        protocol, host, port, path, connection_factory, request_body,
        method='POST', headers=None):
    """
    :param request_body: Request body
    :param connection_factory: Connection class to use. Will be called
        with the host and port arguments.
    :param method: HTTP request method (default: 'POST')

    Perform a HTTP(s) request.
    """
    if isinstance(host, unicode):
        host = host.encode('utf-8')
    uri = '%s://%s%s' % (protocol, ipautil.format_netloc(host, port), path)
    root_logger.debug('request %s %s', method, uri)
    root_logger.debug('request body %r', request_body)

    headers = headers or {}
    if (
        method == 'POST'
        and 'content-type' not in (str(k).lower() for k in headers)
    ):
        headers['content-type'] = 'application/x-www-form-urlencoded'

    try:
        conn = connection_factory(host, port)
        conn.request(method, uri, body=request_body, headers=headers)
        res = conn.getresponse()

        http_status = res.status
        http_headers = res.msg.dict
        http_body = res.read()
        conn.close()
    except Exception as e:
        raise NetworkError(uri=uri, error=str(e))

    root_logger.debug('response status %d',    http_status)
    root_logger.debug('response headers %s',   http_headers)
    root_logger.debug('response body %r',      http_body)

    return http_status, http_headers, http_body
