# Copyright 2008 Red Hat Inc.
# All Rights Reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Authors:
#   Miloslav Trmač <mitr@redhat.com>
#

AM_CPPFLAGS = -I${top_srcdir}/lib
AM_CFLAGS = -D_GNU_SOURCE -Wno-pointer-sign ${WFLAGS}
check_PROGRAMS = lookup_test
TESTS = $(check_PROGRAMS)

lookup_test_LDADD = ${top_builddir}/lib/libaudit.la
lookup_test_DEPENDENCIES = ${top_builddir}/lib/libaudit.la
