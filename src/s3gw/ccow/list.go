package ccow

/*
#include "ccow.h"

int go_ccow_get_list(char* bucket, char* object, ccow_completion_t cpt,
                    char* pattern, int count, ccow_lookup_t* iter)
{
    struct iovec iov = {
        .iov_base = pattern,
        .iov_len = strlen(pattern)
    };

    int bucket_len = strlen(bucket) + 1;
    int object_len = strlen(object) + 1;

    return ccow_get_list(bucket, bucket_len, object, object_len, cpt,
                        &iov, 1, count, iter);
}

*/
import "C"
import "unsafe"

type ListEntry struct {
    Key string
    Val []byte
}

type List []ListEntry

func (ls List) Len() int {
    return len(ls)
}

func (ls List) Swap(i, j int) {
    ls[i], ls[j] = ls[j], ls[i]
}

func (ls List) Less(i, j int) bool {
    return ls[i].Key < ls[j].Key
}

func load_list_raw(iter C.ccow_lookup_t) *List {
    var out = List { }
	var kv *C.struct_ccow_metadata_kv
    mask := C.int(C.CCOW_MDTYPE_NAME_INDEX)

	for {
		kv = (*C.struct_ccow_metadata_kv)(C.ccow_lookup_iter(iter, mask, -1))

		if kv == nil {
			break
		}
		if kv.key_size == 0 {
			continue
		}
		if kv._type != C.CCOW_KVTYPE_RAW {
            continue
        }
        if *kv.key == -17 { // part
            continue
        }

        key := C.GoString(kv.key)
        val := C.GoBytes((unsafe.Pointer)(kv.value), (C.int)(kv.value_size))

        out = append(out, ListEntry{ key, val })
	}

    return &out
}

func (tc *Tenant) Get_List (bucket, object string, pattern string, count int) (*List, error) {
    var ret C.int
    var cpt C.ccow_completion_t
    var iter C.ccow_lookup_t

    ret = C.ccow_create_completion(tc.c, nil, nil, C.int(1), &cpt)

    if ret < 0 {
        return nil, Error("ccow_create_completion", ret)
    }

    defer maybe_release_lookup(iter)

    c_bucket := C.CString(bucket)
    c_object := C.CString(object)
    c_pattern := C.CString(pattern)
    c_count := C.int(count)

    defer C.free(unsafe.Pointer(c_bucket))
    defer C.free(unsafe.Pointer(c_object))
    defer C.free(unsafe.Pointer(c_pattern))

    ret = C.go_ccow_get_list(c_bucket, c_object, cpt, c_pattern, c_count, &iter)

    if ret < 0 {
        return nil, Error("ccow_get_list", ret)
    }

    ret = C.ccow_wait(cpt, 0)

    if ret < 0 {
        return nil, Error("ccow_wait", ret)
    }

    return load_list_raw(iter), nil
}
