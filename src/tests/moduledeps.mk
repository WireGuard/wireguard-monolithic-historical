CONFIG_WIREGUARD := m
ifeq ($(CONFIG_WIREGUARD_PARALLEL),)
ifneq (,$(filter $(CONFIG_PADATA),y m))
ccflags-y += -DCONFIG_WIREGUARD_PARALLEL=y
endif
endif

ifneq ($(CONFIG_MODULES),)
ifeq ($(CONFIG_NETFILTER_XT_MATCH_HASHLIMIT),)
$(error "WireGuard requires CONFIG_NETFILTER_XT_MATCH_HASHLIMIT to be configured in your kernel. See https://www.wireguard.io/install/#kernel-requirements for more info")
endif
ifeq ($(CONFIG_PADATA),)
ifneq ($(CONFIG_SMP),)
$(warning "PEFORMANCE WARNING: WireGuard has enormous speed benefits when using CONFIG_PADATA on SMP systems. Please enable CONFIG_PADATA in your kernel configuration. See https://www.wireguard.io/install/#kernel-requirements for more info.")
endif
endif
endif
