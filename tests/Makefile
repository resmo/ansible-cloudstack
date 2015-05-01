all: cs_exoscale cs_cloudstack

cs_exoscale: export CLOUDSTACK_CONFIG = $(HOME)/.cloudstack.ini.exoscale

cs_exoscale:
#	ansible-playbook cloudstack.yml --tags test_cs_sshkeypair,test_cs_affinitygroup,test_cs_securitygroup,test_cs_securitygroup_rule -v
	ansible-playbook cloudstack.yml --tags test_cs_sshkeypair,test_cs_affinitygroup,test_cs_securitygroup -v

cs_cloudstack:
