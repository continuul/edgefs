package ccow

/*
#include "ccow.h"

int go_ccow_get(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
                ccow_completion_t comp, void* buf, size_t len, uint64_t off, ccow_lookup_t *iter)
{
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = len
    };

    return ccow_get(bid, bid_size, oid, oid_size, comp, &iov, 1, off, iter);
}

int go_ccow_put(const char *bid, size_t bid_size, const char *oid, size_t oid_size,
                ccow_completion_t comp, void* buf, size_t len, uint64_t off)
{
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = len
    };

    return ccow_put(bid, bid_size, oid, oid_size, comp, &iov, 1, off);
}
*/
import "C"
import "unsafe"

func maybe_release_lookup (iter C.ccow_lookup_t) {
    if iter != nil {
        C.ccow_lookup_release(iter)
    }
}

func (tc *Tenant) Get_Meta (bucket, object string) (*Meta, error) {
    var ret C.int
    var cpt C.ccow_completion_t
    var iter C.ccow_lookup_t

    ret = C.ccow_create_completion(tc.c, nil, nil, C.int(1), &cpt)

    if ret < 0 {
        return nil, Error("ccow_create_completion", ret)
    }

    defer C.ccow_release(cpt)
    defer maybe_release_lookup(iter)

    c_bucket := C.CString(bucket)
    c_bucket_len := C.strlen(c_bucket) + 1
    c_object := C.CString(object)
    c_object_len := C.strlen(c_object) + 1

    defer C.free(unsafe.Pointer(c_bucket))
    defer C.free(unsafe.Pointer(c_object))

    ret = C.ccow_get(c_bucket, c_bucket_len, c_object, c_object_len,
                     cpt, nil, 0, 0, &iter)

    if ret < 0 {
        return nil, Error("ccow_get", ret)
    }

    ret = C.ccow_wait(cpt, 0)

    if ret < 0 {
        return nil, Error("ccow_wait", ret)
    }
    if iter == nil {
        return nil, nil
    }

    attrs := lookup_to_meta(iter)

    return attrs, nil
}

func (tc *Tenant) Get (bucket, object string, buf []byte, off uint64) error {
    var cpt C.ccow_completion_t
    var ret C.int

    ret = C.ccow_create_completion(tc.c, nil, nil, C.int(1), &cpt)
    if ret < 0 {
        return Error("ccow_create_completion", ret)
    }

    c_bucket := C.CString(bucket)
    c_bucket_len := C.strlen(c_bucket) + 1
    c_object := C.CString(object)
    c_object_len := C.strlen(c_object) + 1

    defer C.free(unsafe.Pointer(c_bucket))
    defer C.free(unsafe.Pointer(c_object))

    c_off := C.uint64_t(off)
    c_buf := unsafe.Pointer(&buf[0])
    c_len := C.ulong(len(buf))

    ret = C.go_ccow_get(c_bucket, c_bucket_len, c_object, c_object_len,
                         cpt, c_buf, c_len, c_off, nil)

    if ret < 0 {
        return Error("ccow_get", ret)
    }

    ret = C.ccow_wait(cpt, 0)

    if ret < 0 {
        return Error("ccow_wait", ret)
    }

    return nil
}

func (tc *Tenant) Put (bucket, object string, buf []byte, off uint64) error {
    var cpt C.ccow_completion_t
    var ret C.int

    ret = C.ccow_create_completion(tc.c, nil, nil, C.int(1), &cpt)

    if ret < 0 {
        return Error("ccow_create_completion", ret)
    }

    c_bucket := C.CString(bucket)
    c_bucket_len := C.strlen(c_bucket) + 1
    c_object := C.CString(object)
    c_object_len := C.strlen(c_object) + 1

    defer C.free(unsafe.Pointer(c_bucket))
    defer C.free(unsafe.Pointer(c_object))

    c_off := C.uint64_t(off)
    c_buf := unsafe.Pointer(&buf[0])
    c_len := C.ulong(len(buf))

    ret = C.go_ccow_put(c_bucket, c_bucket_len, c_object, c_object_len,
                        cpt, c_buf, c_len, c_off)

    if ret < 0 {
        return Error("ccow_put", ret)
    }

    ret = C.ccow_wait(cpt, 0)

    if ret < 0 {
        return Error("ccow_wait", ret)
    }

    return nil
}

func (tc *Tenant) Put_Empty_Object (bucket, object string) error {
    var cpt C.ccow_completion_t
    var ret C.int

    ret = C.ccow_create_completion(tc.c, nil, nil, C.int(1), &cpt)

    if ret < 0 {
        return Error("ccow_create_completion", ret)
    }

    c_bucket := C.CString(bucket)
    c_bucket_len := C.strlen(c_bucket) + 1
    c_object := C.CString(object)
    c_object_len := C.strlen(c_object) + 1

    defer C.free(unsafe.Pointer(c_bucket))
    defer C.free(unsafe.Pointer(c_object))

    ret = C.ccow_put(c_bucket, c_bucket_len, c_object, c_object_len, cpt, nil, 0, 0)

    if ret < 0 {
        return Error("ccow_put", ret)
    }

    ret = C.ccow_wait(cpt, 0)

    if ret < 0 {
        return Error("ccow_wait", ret)
    }

    return nil
}
