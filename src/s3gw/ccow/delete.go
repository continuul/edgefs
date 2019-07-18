package ccow

/*
#include "ccow.h"
*/
import "C"
import "unsafe"

func (tc *Tenant) Delete_Object (bucket, object string) error {
    var ret C.int
    var cpt C.ccow_completion_t

    ret = C.ccow_create_completion(tc.c, nil, nil, C.int(1), &cpt)

    if ret < 0 {
        return Error("ccow_create_completion", ret)
    }

    defer C.ccow_release(cpt)

    c_bucket := C.CString(bucket)
    c_bucket_len := C.strlen(c_bucket) + 1
    c_object := C.CString(object)
    c_object_len := C.strlen(c_object) + 1

    defer C.free(unsafe.Pointer(c_bucket))
    defer C.free(unsafe.Pointer(c_object))

    ret = C.ccow_delete(c_bucket, c_bucket_len, c_object, c_object_len, cpt)

    if ret < 0 {
        return Error("ccow_delete", ret)
    }

    ret = C.ccow_wait(cpt, 0)

    if ret < 0 {
        return Error("ccow_wait", ret)
    }

    tc.flush_object(bucket, object)

    return nil
}
