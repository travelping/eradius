#    __                        __      _
#   / /__________ __   _____  / /___  (_)___  ____ _
#  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
# / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
# \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
#                           /_/            /____/
#
# Copyright (c) Travelping GmbH <info@travelping.com>

APPNAME = eradius
VERSION = 0.0.0

ERL  = erl
ERLC = erlc

DESTDIR     = /
ERL_LIB_DIR = `$(ERL) -noinput -eval 'io:format("~s",[code:lib_dir()]), halt(0).'`
INSTDIR     = "$(DESTDIR)/$(ERL_LIB_DIR)/$(APPNAME)-$(VERSION)"
ERLRC_ROOT  = "$(DESTDIR)/etc/erlrc.d"

SRC_DIR     = $(PWD)/src
EBIN_DIR    = $(PWD)/ebin
INCLUDE_DIR = $(PWD)/include
PRIV_DIR    = $(PWD)/priv
