# Makefile.am --
# Copyright 2025 Red Hat Inc.
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
# License along with this program; see the file COPYING.lib. If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
# Boston, MA 02110-1335, USA.
#
# Authors:
#   Steve Grubb <sgrubb@redhat.com>

AM_CPPFLAGS = -D_GNU_SOURCE -I${top_srcdir} -I${top_srcdir}/audisp \
	-I${top_srcdir}/common -I${top_srcdir}/src -I${top_srcdir}/lib
AM_CFLAGS = -D_GNU_SOURCE -Wno-pointer-sign ${WFLAGS}
check_PROGRAMS = audisp-queue-test audisp-llist-test
TESTS = $(check_PROGRAMS)

audisp_queue_test_SOURCES = test-queue.c
audisp_queue_test_LDADD = ${top_builddir}/audisp/libqueue.la \
	${top_builddir}/common/libaucommon.la -lpthread

audisp_llist_test_SOURCES = test-audispd-llist.c
audisp_llist_test_LDADD = ${top_builddir}/audisp/libdisp.la \
	${top_builddir}/common/libaucommon.la

