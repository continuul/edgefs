package ccow

/*
#include "ccow.h"
*/
import "C"
import "unsafe"

func (tc *Tenant) Create_Bucket (bucket string) error {
    var cpt C.ccow_completion_t
    var ret C.int

    c_bucket := C.CString(bucket)
    c_bucket_len := C.strlen(c_bucket) + 1
    defer C.free(unsafe.Pointer(c_bucket))

    ret = C.ccow_create_completion(tc.c, nil, nil, C.int(1), &cpt)

    if ret < 0 {
        return Error("ccow_create_completion", ret)
    }

    defer C.ccow_release(cpt)

    ret = C.ccow_bucket_create(tc.c, c_bucket, c_bucket_len, cpt)

    if ret < 0 {
        return Error("ccow_bucket_create", ret)
    }

    ret = C.ccow_wait(cpt, 0)

    if ret < 0 {
        return Error("ccow_wait", ret)
    }

    return nil
}

func (tc *Tenant) Delete_Bucket (bucket string) error {
    c_bucket := C.CString(bucket)
    c_bucket_len := C.strlen(c_bucket) + 1
    defer C.free(unsafe.Pointer(c_bucket))

    ret := C.ccow_bucket_delete(tc.c, c_bucket, c_bucket_len)

    if ret < 0 {
        return Error("ccow_bucket_delete", ret)
    }

    tc.flush_bucket(bucket)

    return nil
}
