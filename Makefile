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
	$(ERL) -noinput -eval "case make:all() of up_to_date -> halt(0); error -> halt(1) end."
	$(MAKE) -C $(PRIV_DIR)

clean:
	rm -f $(EBIN_DIR)/*.beam
	$(MAKE) -C $(PRIV_DIR) clean

install: all debian-hooks
	mkdir -p $(INSTDIR)
	cp -r $(EBIN_DIR) $(PRIV_DIR) $(INCLUDE_DIR) $(INSTDIR)
	mkdir -p $(ERLRC_ROOT)/applications
	touch $(ERLRC_ROOT)/applications/$(APPNAME)

deb: debian-hooks
	dpkg-buildpackage -b

debian-hooks:
	sed -e "s,@APPNAME@,$(APPNAME),; s,@VERSION@,$(VERSION)," <debian/postinst.in >debian/postinst
	sed -e "s,@APPNAME@,$(APPNAME),; s,@VERSION@,$(VERSION)," <debian/prerm.in >debian/prerm
	sed -e "s,@APPNAME@,$(APPNAME),; s,@VERSION@,$(VERSION)," <debian/postrm.in >debian/postrm
	sed -e "s,@APPNAME@,$(APPNAME),; s,@VERSION@,$(VERSION)," <debian/changelog.in >debian/changelog

shell: all
	$(ERL) -pa $(EBIN_DIR)
