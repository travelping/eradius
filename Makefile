#    __                        __      _
#   / /__________ __   _____  / /___  (_)___  ____ _
#  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
# / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
# \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
#                           /_/            /____/
#
# Copyright (c) Travelping GmbH <info@travelping.com>

include master.mk

.PHONY: all clean install shell 

all:
	$(ERL) -noinput -eval "case make:all([{d, 'TEST'}]) of up_to_date -> halt(0); error -> halt(1) end."
	$(MAKE) -C $(PRIV_DIR)

clean:
	rm -f $(EBIN_DIR)/*.beam
	$(MAKE) -C $(PRIV_DIR) clean

shell: all
	$(ERL) -pa $(EBIN_DIR)
