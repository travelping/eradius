#    __                        __      _
#   / /__________ __   _____  / /___  (_)___  ____ _
#  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
# / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
# \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
#                           /_/            /____/
#
# Copyright (c) Travelping GmbH <info@travelping.com>

include ../master.mk

DICTFILES := $(wildcard dictionaries/*.*)
DICTMAPS := $(patsubst dictionaries/dictionary.%,dictionary_%.map,$(DICTFILES))

.PHONY: dictionaries clean

dictionaries: dictionary.map $(DICTMAPS)

clean: 
	rm -f $(DICTMAPS)

dictionary.map: dictionaries/dictionary
	$(ERL) -noshell -pa $(EBIN_DIR) -s eradius_dict make $< || exit 1;

dictionary_%.map: dictionaries/dictionary.%
	$(ERL) -noshell -pa $(EBIN_DIR) -s eradius_dict make $< || exit 1;
