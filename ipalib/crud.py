# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Base classes for standard CRUD operations.
"""

import frontend, errors


class Add(frontend.Method):
    def get_options(self):
        assert 'params' in self.obj, list(self.obj)
        return self.obj.params()


class Get(frontend.Method):
    pass


class Del(frontend.Method):
    pass


class Mod(frontend.Method):
    pass


class Find(frontend.Method):
    pass
