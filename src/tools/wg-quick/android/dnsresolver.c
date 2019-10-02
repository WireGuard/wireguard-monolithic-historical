#include <stdio.h>
#include <stdlib.h>
#include <uchar.h>
#include <string.h>

#include "dnsresolver.h"
#include "binder_ndk.h"

#define DNSRESOLVER_DESCRIPTOR "android.net.IDnsResolver"

static void *on_create()
{
	fprintf(stderr, "Error: on_create called on proxy object\n");
	exit(ENOTSUP);
}

static void on_destroy()
{
	fprintf(stderr, "Error: on_destroy called on proxy object\n");
	exit(ENOTSUP);
}

static binder_status_t on_transact()
{
	fprintf(stderr, "Error: on_transact called on a proxy object\n");
	exit(ENOTSUP);
}

void *dnsresolver_get_handle(void)
{
	if (!binder_is_available()) {
		return NULL;
	}

	AIBinder *binder;
	AIBinder_Class *clazz;

	binder = AServiceManager_getService("dnsresolver");
	if (!binder)
		return NULL;
	clazz = AIBinder_Class_define(DNSRESOLVER_DESCRIPTOR, &on_create, &on_destroy, &on_transact);
	if (!clazz)
		goto error;

	if (!AIBinder_associateClass(binder, clazz))
		goto error;

	return binder;
error:
	AIBinder_decStrong(binder);
	return NULL;
}

void dnsresolver_dec_ref(void *handle)
{
	AIBinder *const binder = handle;
	AIBinder_decStrong(binder);
}

int32_t dnsresolver_is_alive(void *handle, bool *aidl_return)
{
	AIBinder *const binder = handle;
	binder_status_t status;
	_cleanup_parcel_ AParcel *parcel_in = NULL;
	_cleanup_parcel_ AParcel *parcel_out = NULL;
	_cleanup_status_ AStatus *status_out = NULL;

	status = AIBinder_prepareTransaction(binder, &parcel_in);
	if (status != STATUS_OK)
		return status;

	status = AIBinder_transact(binder, FIRST_CALL_TRANSACTION + 0 /* isAlive */, &parcel_in, &parcel_out, 0);
	if (status != STATUS_OK)
		return status;

	status = AParcel_readStatusHeader(parcel_out, &status_out);
	if (status != STATUS_OK)
		return status;

	if (!AStatus_isOk(status_out))
		return meaningful_binder_status(status_out);

	return AParcel_readBool(parcel_out, aidl_return);
}

int32_t dnsresolver_create_network_cache(void *handle, int32_t netid)
{
	AIBinder *const binder = handle;
	binder_status_t status;
	_cleanup_parcel_ AParcel *parcel_in = NULL;
	_cleanup_parcel_ AParcel *parcel_out = NULL;
	_cleanup_status_ AStatus *status_out = NULL;

	status = AIBinder_prepareTransaction(binder, &parcel_in);
	if (status != STATUS_OK)
		return status;

	status = AParcel_writeInt32(parcel_in, netid);
	if (status != STATUS_OK)
		return status;

	status = AIBinder_transact(binder, FIRST_CALL_TRANSACTION + 7 /* createNetworkCache */, &parcel_in, &parcel_out, 0);
	if (status != STATUS_OK)
		return status;

	status = AParcel_readStatusHeader(parcel_out, &status_out);
	if (status != STATUS_OK)
		return status;

	if (!AStatus_isOk(status_out))
		return meaningful_binder_status(status_out);

	return STATUS_OK;
}

int32_t dnsresolver_destroy_network_cache(void *handle, int32_t netid)
{
	AIBinder *const binder = handle;
	binder_status_t status;
	_cleanup_parcel_ AParcel *parcel_in = NULL;
	_cleanup_parcel_ AParcel *parcel_out = NULL;
	_cleanup_status_ AStatus *status_out = NULL;

	status = AIBinder_prepareTransaction(binder, &parcel_in);
	if (status != STATUS_OK)
		return status;

	status = AParcel_writeInt32(parcel_in, netid);
	if (status != STATUS_OK)
		return status;

	status = AIBinder_transact(binder, FIRST_CALL_TRANSACTION + 8 /* destroyNetworkCache */, &parcel_in, &parcel_out, 0);
	if (status != STATUS_OK)
		return status;

	status = AParcel_readStatusHeader(parcel_out, &status_out);
	if (status != STATUS_OK)
		return status;

	if (!AStatus_isOk(status_out))
		return meaningful_binder_status(status_out);

	return STATUS_OK;
}

int32_t dnsresolver_set_log_severity(void *handle, int32_t log_severity)
{
	AIBinder *const binder = handle;
	binder_status_t status;
	_cleanup_parcel_ AParcel *parcel_in = NULL;
	_cleanup_parcel_ AParcel *parcel_out = NULL;
	_cleanup_status_ AStatus *status_out = NULL;

	status = AIBinder_prepareTransaction(binder, &parcel_in);
	if (status != STATUS_OK)
		return status;

	status = AParcel_writeInt32(parcel_in, log_severity);
	if (status != STATUS_OK)
		return status;

	status = AIBinder_transact(binder, FIRST_CALL_TRANSACTION + 9 /* setLogSeverity */, &parcel_in, &parcel_out, 0);
	if (status != STATUS_OK)
		return status;

	status = AParcel_readStatusHeader(parcel_out, &status_out);
	if (status != STATUS_OK)
		return status;

	if (!AStatus_isOk(status_out))
		return meaningful_binder_status(status_out);

	return STATUS_OK;
}

int32_t dnsresolver_set_resolver_configuration(void *handle, const struct resolver_params *params)
{
	AIBinder *const binder = handle;
	binder_status_t status;
	_cleanup_parcel_ AParcel *parcel_in = NULL;
	_cleanup_parcel_ AParcel *parcel_out = NULL;
	_cleanup_status_ AStatus *status_out = NULL;
	int32_t start_position, end_position;

	status = AIBinder_prepareTransaction(binder, &parcel_in);
	if (status != STATUS_OK)
		return status;

	status = AParcel_writeInt32(parcel_in, 1);
	if (status != STATUS_OK)
		return status;

	start_position = AParcel_getDataPosition(parcel_in);
	status = AParcel_writeInt32(parcel_in, 0);
	if (status != STATUS_OK)
		return status;

	status = AParcel_writeInt32(parcel_in, params->netid);
	if (status != STATUS_OK)
		return status;
	status = AParcel_writeInt32(parcel_in, params->sample_validity_seconds);
	if (status != STATUS_OK)
		return status;
	status = AParcel_writeInt32(parcel_in, params->success_threshold);
	if (status != STATUS_OK)
		return status;
	status = AParcel_writeInt32(parcel_in, params->min_samples);
	if (status != STATUS_OK)
		return status;
	status = AParcel_writeInt32(parcel_in, params->max_samples);
	if (status != STATUS_OK)
		return status;
	status = AParcel_writeInt32(parcel_in, params->base_timeout_msec);
	if (status != STATUS_OK)
		return status;
	status = AParcel_writeInt32(parcel_in, params->retry_count);
	if (status != STATUS_OK)
		return status;
	status = AParcel_writeStringArray(parcel_in, params->servers, string_array_size(params->servers), &string_array_getter);
	if (status != STATUS_OK)
		return status;
	status = AParcel_writeStringArray(parcel_in, params->domains, string_array_size(params->domains), &string_array_getter);
	if (status != STATUS_OK)
		return status;
	status = AParcel_writeString(parcel_in, params->tls_name, string_size(params->tls_name));
	if (status != STATUS_OK)
		return status;
	status = AParcel_writeStringArray(parcel_in, params->tls_servers, string_array_size(params->tls_servers), &string_array_getter);
	if (status != STATUS_OK)
		return status;
	status = AParcel_writeStringArray(parcel_in, params->tls_fingerprints, string_array_size(params->tls_fingerprints), &string_array_getter);
	if (status != STATUS_OK)
		return status;

	end_position = AParcel_getDataPosition(parcel_in);
	status = AParcel_setDataPosition(parcel_in, start_position);
	if (status != STATUS_OK)
		return status;
	status = AParcel_writeInt32(parcel_in, end_position - start_position);
	if (status != STATUS_OK)
		return status;
	status = AParcel_setDataPosition(parcel_in, end_position);
	if (status != STATUS_OK)
		return status;

	status = AIBinder_transact(binder, FIRST_CALL_TRANSACTION + 2 /* setResolverConfiguration */, &parcel_in, &parcel_out, 0);
	if (status != STATUS_OK)
		return status;

	status = AParcel_readStatusHeader(parcel_out, &status_out);
	if (status != STATUS_OK)
		return status;

	return meaningful_binder_status(status_out);
}

void dnsresolver_dump(void *handle, int fd)
{
	AIBinder *const binder = handle;
	AIBinder_dump(binder, fd, NULL, 0);
}

int32_t dnsresolver_ping(void *handle)
{
	AIBinder *const binder = handle;
	return AIBinder_ping(binder);
}

void cleanup_dnsresolver(void **handle)
{
	dnsresolver_dec_ref(*handle);
}
