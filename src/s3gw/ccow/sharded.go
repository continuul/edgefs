package ccow

/*
#include "ccow.h"
*/
import "C"
import "unsafe"

type ShardedList map[string][]byte

func load_sharded_raw(iter C.ccow_lookup_t) *ShardedList {
    var out = ShardedList { }
	var kv *C.struct_ccow_metadata_kv

	for {
		kv = (*C.struct_ccow_metadata_kv)(C.ccow_lookup_iter(iter, -1, -1))

		if kv == nil {
			break
		}
		if kv.key_size == 0 {
			continue
		}
		if kv._type != C.CCOW_KVTYPE_RAW {
            continue
        }

        key := C.GoString(kv.key)
        val := C.GoBytes((unsafe.Pointer)(kv.value), (C.int)(kv.value_size))

        out[key] = val
	}

    return &out
}

func (tc *Tenant) Sharded_Get_List (bucket string, name string, shards int,
                marker string, count int) (*ShardedList, error) {
    var shct C.ccow_shard_context_t
    var iter C.ccow_lookup_t

    c_bucket := C.CString(bucket)
    c_bucket_len := C.strlen(c_bucket) + 1
    defer C.free(unsafe.Pointer(c_bucket))

    c_name := C.CString(name)
    c_name_len := C.strlen(c_name) + 1
    defer C.free(unsafe.Pointer(c_name))

    c_marker := C.CString(marker)
    c_marker_len := C.strlen(c_marker) + 1
    defer C.free(unsafe.Pointer(c_marker))

    c_shards := C.int(shards)
    c_count := C.int(count)

    ret := C.ccow_shard_context_create(c_name, c_name_len, c_shards, &shct)

    if ret < 0 {
        return nil, Error("ccow_shard_context_create", ret)
    }

    defer C.ccow_shard_context_destroy(&shct)

    ret = C.ccow_sharded_get_list(tc.c, c_bucket, c_bucket_len, shct,
                c_marker, c_marker_len, nil, c_count, &iter)

    defer C.ccow_lookup_release(iter)

    if ret < 0 {
        return nil, Error("ccow_shared_get_list", ret)
    }

    return load_sharded_raw(iter), nil
}
