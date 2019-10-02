#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#define _cleanup_status_ __attribute__((__cleanup__(cleanup_status)))
#define _cleanup_parcel_ __attribute__((__cleanup__(cleanup_parcel)))
#define _cleanup_binder_ __attribute__((__cleanup__(cleanup_binder)))

bool binder_is_available(void);

typedef int32_t binder_status_t;
typedef int32_t binder_exception_t;
typedef uint32_t transaction_code_t;
typedef uint32_t binder_flags_t;

/* values are from AOSP repository platform/frameworks/native
 * in libs/binder/ndk/include_ndk/android/binder_status.h
 */

enum {
	STATUS_OK = 0,
	STATUS_UNKNOWN_ERROR = -2147483647 - 1,
	STATUS_NO_MEMORY = -ENOMEM,
	STATUS_INVALID_OPERATION = -ENOSYS,
	STATUS_BAD_VALUE = -EINVAL,
	STATUS_BAD_TYPE = STATUS_UNKNOWN_ERROR + 1,
	STATUS_NAME_NOT_FOUND = -ENOENT,
	STATUS_PERMISSION_DENIED = -EPERM,
	STATUS_NO_INIT = -ENODEV,
	STATUS_ALREADY_EXISTS = -EEXIST,
	STATUS_DEAD_OBJECT = -EPIPE,
	STATUS_FAILED_TRANSACTION = STATUS_UNKNOWN_ERROR + 2,
	STATUS_BAD_INDEX = -EOVERFLOW,
	STATUS_NOT_ENOUGH_DATA = -ENODATA,
	STATUS_WOULD_BLOCK = -EWOULDBLOCK,
	STATUS_TIMED_OUT = -ETIMEDOUT,
	STATUS_UNKNOWN_TRANSACTION = -EBADMSG,
	STATUS_FDS_NOT_ALLOWED = STATUS_UNKNOWN_ERROR + 7,
	STATUS_UNEXPECTED_NULL = STATUS_UNKNOWN_ERROR + 8
};

enum {
	EX_NONE = 0,
	EX_SECURITY = -1,
	EX_BAD_PARCELABLE = -2,
	EX_ILLEGAL_ARGUMENT = -3,
	EX_NULL_POINTER = -4,
	EX_ILLEGAL_STATE = -5,
	EX_NETWORK_MAIN_THREAD = -6,
	EX_UNSUPPORTED_OPERATION = -7,
	EX_SERVICE_SPECIFIC = -8,
	EX_PARCELABLE = -9,
	EX_TRANSACTION_FAILED = -129
};

enum {
	FLAG_ONEWAY = 0x01,
};

enum {
	FIRST_CALL_TRANSACTION = 0x00000001,
	LAST_CALL_TRANSACTION = 0x00ffffff
};

struct AIBinder;
struct AParcel;
struct AStatus;
struct AIBinder_Class;

typedef struct AIBinder AIBinder;
typedef struct AParcel AParcel;
typedef struct AStatus AStatus;
typedef struct AIBinder_Class AIBinder_Class;

typedef void *(*AIBinder_Class_onCreate)(void *args);
typedef void (*AIBinder_Class_onDestroy)(void *userData);
typedef binder_status_t (*AIBinder_Class_onTransact)(AIBinder *binder, transaction_code_t code, const AParcel *in, AParcel *out);
typedef const char *(*AParcel_stringArrayElementGetter)(const void *arrayData, size_t index, int32_t *outLength);

/* function pointers to the libbinder_ndk.so symbols,
 * NULL if they cannot be loaded */
extern AIBinder_Class *(*AIBinder_Class_define)(const char *interfaceDescriptor, AIBinder_Class_onCreate onCreate, AIBinder_Class_onDestroy onDestroy, AIBinder_Class_onTransact onTransact) __attribute__((warn_unused_result));
extern bool (*AIBinder_associateClass)(AIBinder *binder, const AIBinder_Class *clazz);
extern void (*AIBinder_decStrong)(AIBinder *binder);
extern binder_status_t (*AIBinder_prepareTransaction)(AIBinder *binder, AParcel **in);
extern binder_status_t (*AIBinder_transact)(AIBinder *binder, transaction_code_t code, AParcel **in, AParcel **out, binder_flags_t flags);
extern binder_status_t (*AIBinder_ping)(AIBinder *binder);
extern binder_status_t (*AIBinder_dump)(AIBinder *binder, int fd, const char **args, uint32_t numArgs);
extern binder_status_t (*AParcel_readStatusHeader)(const AParcel *parcel, AStatus **status);
extern binder_status_t (*AParcel_readBool)(const AParcel *parcel, bool *value);
extern void (*AParcel_delete)(AParcel *parcel);
extern binder_status_t (*AParcel_setDataPosition)(const AParcel *parcel, int32_t position);
extern int32_t (*AParcel_getDataPosition)(const AParcel *parcel);
extern binder_status_t (*AParcel_writeInt32)(AParcel *parcel, int32_t value);
extern binder_status_t (*AParcel_writeStringArray)(AParcel *parcel, const void *arrayData, int32_t length, AParcel_stringArrayElementGetter getter);
extern binder_status_t (*AParcel_readStatusHeader)(const AParcel *parcel, AStatus **status);
extern binder_status_t (*AParcel_writeString)(AParcel *parcel, const char *string, int32_t length);
extern bool (*AStatus_isOk)(const AStatus *status);
extern void (*AStatus_delete)(AStatus *status);
extern binder_exception_t (*AStatus_getExceptionCode)(const AStatus *status);
extern int32_t (*AStatus_getServiceSpecificError)(const AStatus *status);
extern const char* (*AStatus_getMessage)(const AStatus *status);
extern binder_status_t (*AStatus_getStatus)(const AStatus *status);
extern AIBinder *(*AServiceManager_getService)(const char *instance) __attribute__((__warn_unused_result__));

void cleanup_binder(AIBinder **);
void cleanup_status(AStatus **);
void cleanup_parcel(AParcel **);

static inline int32_t string_size(const char *str)
{
	return str ? strlen(str) : -1;
}

static inline int32_t string_array_size(char *const *array)
{
	int32_t size = -1;
	if (!array)
		return size;
	for (size = 0; array[size]; ++size);
	return size;
}

static inline const char *string_array_getter(const void *array_data, size_t index, int32_t *outlength)
{
	const char **array = (const char **)array_data;
	*outlength = array[index] ? strlen(array[index]) : -1;
	return array[index];
}

binder_status_t meaningful_binder_status(const AStatus *status_out);
