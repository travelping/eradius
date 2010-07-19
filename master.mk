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

TOP        := $(dir $(lastword $(MAKEFILE_LIST)))
SRC_DIR     = $(TOP)/src
EBIN_DIR    = $(TOP)/ebin
INCLUDE_DIR = $(TOP)/include
PRIV_DIR    = $(TOP)/priv
