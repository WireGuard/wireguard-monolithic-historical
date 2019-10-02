#pragma once

#include <stdint.h>
#include <stdbool.h>

#define _cleanup_dnsresolver_ __attribute__((__cleanup__(cleanup_dnsresolver)))

struct resolver_params {
	int32_t netid;
	int32_t sample_validity_seconds;
	int32_t success_threshold;
	int32_t min_samples;
	int32_t max_samples;
	int32_t base_timeout_msec;
	int32_t retry_count;
	char **servers;          /* NULL terminated array of zero-terminated UTF-8 strings */
	char **domains;          /* NULL terminated array of zero-terminated UTF-8 strings */
	char *tls_name;          /* zero-terminated UTF-8 string													 */
	char **tls_servers;      /* NULL terminated array of zero-terminated UTF-8 strings */
	char **tls_fingerprints; /* NULL terminated array of zero-terminated UTF-8 strings */
};

/*
 * the int32_t return codes below are 0 if there is no error,
 * see binder_status_t in binder_ndk.h for the meaning of other values
 */
void *dnsresolver_get_handle(void) __attribute__((__warn_unused_result__));
void dnsresolver_dec_ref(void *handle);
int32_t dnsresolver_set_resolver_configuration(void *handle, const struct resolver_params *params);
int32_t dnsresolver_create_network_cache(void *handle, int32_t netid);
int32_t dnsresolver_destroy_network_cache(void *handle, int32_t netid);

int32_t dnsresolver_is_alive(void *handle, bool *result);
int32_t dnsresolver_set_log_severity(void *handle, int32_t log_severity);
void dnsresolver_dump(void *handle, int fd);
int32_t dnsresolver_ping(void *handle);

void cleanup_dnsresolver(void **handle);
