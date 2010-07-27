#    __                        __      _
#   / /__________ __   _____  / /___  (_)___  ____ _
#  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
# / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
# \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
#                           /_/            /____/
#
# Copyright (c) Travelping GmbH <info@travelping.com>

ERL  = erl
ERLC = erlc

TOP        := $(dir $(lastword $(MAKEFILE_LIST)))
SRC_DIR     = $(TOP)/src
EBIN_DIR    = $(TOP)/ebin
INCLUDE_DIR = $(TOP)/include
PRIV_DIR    = $(TOP)/priv
