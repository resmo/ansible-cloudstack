INVENTORY ?= inventory
VARS_FILE ?= integration_config.yml

# Create a semi-random string for use when testing cloud-based resources
ifndef CLOUD_RESOURCE_PREFIX
CLOUD_RESOURCE_PREFIX := $(shell python -c "import string,random; print 'ansible-testing-' + ''.join(random.choice(string.ascii_letters + string.digits) for _ in xrange(8));")
endif

CREDENTIALS_FILE = credentials.yml
# If credentials.yml exists, use it
ifneq ("$(wildcard $(CREDENTIALS_FILE))","")
CREDENTIALS_ARG = -e @$(CREDENTIALS_FILE)
else
CREDENTIALS_ARG =
endif

cloudstack:
	ansible-playbook cloudstack.yml -i $(INVENTORY) -e @$(VARS_FILE) -e "resource_prefix=$(CLOUD_RESOURCE_PREFIX)" -v $(TEST_FLAGS) ; \
	RC=$$? ; \
	exit $$RC;
