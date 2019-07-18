package ccow

/* The C wrappers below are needed to avoid "Go pointer to a Go pointer" error
   in []byte to iovec conversion. Current implementation does not use multiple
   buffers at all. */

/*
#include "ccow.h"

int go_ccow_get_cont(ccow_completion_t cpt, void* buf, size_t len, uint64_t off, int* io_count)
{
    int ret;

    struct iovec iov = {
        .iov_base = buf,
        .iov_len = len
    };

    if ((ret = ccow_get_cont(cpt, &iov, 1, off, 1, io_count)) < 0)
        return ret;

    return ccow_wait(cpt, *io_count);
}

int go_ccow_put_cont(ccow_completion_t cpt, void* buf, size_t len, uint64_t off, int* io_count)
{
    int ret;

    struct iovec iov = {
        .iov_base = buf,
        .iov_len = len
    };

    if ((ret = ccow_put_cont(cpt, &iov, 1, off, 1, io_count)) < 0)
        return ret;

    return ccow_wait(cpt, *io_count);
}

*/
import "C"
import "unsafe"

type Stream struct {
    tc *Tenant

    bucket string
    object string

    cpt C.ccow_completion_t
    iter C.ccow_lookup_t

    io_count C.int
    max_io_count C.int

    genid C.uint64_t
    flags C.int

    writable bool
}

func create_stream_completion (sr *Stream) error {
    c_bucket := C.CString(sr.bucket)
    c_bucket_len := C.strlen(c_bucket) + 1
    c_object := C.CString(sr.object)
    c_object_len := C.strlen(c_object) + 1
    c_opnum := C.int(sr.max_io_count)

	defer C.free(unsafe.Pointer(c_bucket))
	defer C.free(unsafe.Pointer(c_object))

    ret := C.ccow_create_stream_completion(sr.tc.c, nil, nil, c_opnum, &sr.cpt,
            c_bucket, c_bucket_len, c_object, c_object_len,
            &sr.genid, &sr.flags, &sr.iter)

    if ret < 0 {
        return Error("ccow_create_stream_completion", ret)
    }

    return nil
}

func finalize_stream (sr *Stream) error {
    if sr.writable {
        ret := C.ccow_finalize(sr.cpt, &sr.iter)
        if ret < 0 { return Error("ccow_finalize", ret) }
    } else {
        ret := C.ccow_cancel(sr.cpt)
        if ret < 0 { return Error("ccow_cancel", ret) }
    }

    return nil
}

func maybe_reopen_stream (sr *Stream) error {
    if sr.io_count < sr.max_io_count {
        return nil
    }

    if err := finalize_stream(sr); err != nil {
        return err
    }

    release_stream(sr)

    if err := create_stream_completion(sr); err != nil {
        return err
    }

    sr.io_count = C.int(0)

    return nil
}

func release_stream (sr *Stream) {
    C.ccow_release(sr.cpt)
    sr.cpt = nil
}

func (tc *Tenant) Open_Read_Stream (bucket, object string, iocount uint) (*Stream, error) {
    sr := Stream {
        tc: tc,
        bucket: bucket,
        object: object,
        max_io_count: C.int(iocount),
        io_count: 0,
        writable: false,
        flags: 0,
    }

    if err := create_stream_completion(&sr); err != nil {
        return nil, err
    }

    return &sr, nil
}

func (tc *Tenant) Open_Write_Stream (bucket, object string, iocount uint) (*Stream, error) {
    sr := Stream {
        tc: tc,
        bucket: bucket,
        object: object,
        max_io_count: C.int(iocount),
        io_count: 0,
        writable: true,
        flags: C.CCOW_CONT_F_REPLACE,
    }

    if err := create_stream_completion(&sr); err != nil {
        return nil, err
    }

    return &sr, nil
}

func (sr *Stream) Get_Chunk (buf []byte, off uint64) error {
    if err := maybe_reopen_stream(sr); err != nil {
        return err
    }

    c_buf := unsafe.Pointer(&buf[0])
    c_len := C.ulong(len(buf))
    c_off := C.uint64_t(off)

    ret := C.go_ccow_get_cont(sr.cpt, c_buf, c_len, c_off, &sr.io_count)

    if ret < 0 {
        return Error("ccow_get_cont", ret)
    }

    return nil
}

func (sr *Stream) Put_Chunk (buf []byte, off uint64) error {
    if err := maybe_reopen_stream(sr); err != nil {
        return err
    }

    c_buf := unsafe.Pointer(&buf[0])
    c_len := C.ulong(len(buf))
    c_off := C.uint64_t(off)

    ret := C.go_ccow_put_cont(sr.cpt, c_buf, c_len, c_off, &sr.io_count)

    if ret < 0 {
        return Error("ccow_put_cont", ret)
    }

    return nil
}

func (sr *Stream) Put_No_Data () error {
    if ret := C.ccow_put_cont(sr.cpt, nil, 0, 0, 1, &sr.io_count); ret < 0 {
        return Error("ccow_put_cont", ret)
    }
    if ret := C.ccow_wait(sr.cpt, sr.io_count); ret < 0 {
        return Error("ccow_put_cont", ret)
    }

    return nil
}

func (sr *Stream) Stop () error {
    if err := finalize_stream(sr); err != nil {
        return err
    }

    return nil
}

func (sr *Stream) Finalize () (*Meta, error) {
    if err := finalize_stream(sr); err != nil {
        return nil, err
    }
    if sr.iter == nil {
        return nil, nil
    }

    attrs := lookup_to_meta(sr.iter)

    return attrs, nil
}

func (sr *Stream) Release () {
    release_stream(sr)
}

func (sr *Stream) Get_Default_Chunk_Size() uint {
    /* missing in Nedge */
    //size := C.ccow_chunk_size(sr.cpt)
	//return uint(size)

    return 1024*1024
}

func (sr *Stream) Set_Chunk_Size_Attr (size uint) error {
    c_size := C.uint32_t(size)

	ret := C.ccow_attr_modify_default(sr.cpt,
        C.CCOW_ATTR_CHUNKMAP_CHUNK_SIZE, unsafe.Pointer(&c_size), nil)

    if ret < 0 {
        return Error("ccow_attr_modify_default", ret)
    }

    return nil
}

func (sr *Stream) Object_Exists () bool {
    return ((sr.flags & C.CCOW_CONT_F_EXIST) != 0)
}

func (sr *Stream) Get_Meta () *Meta {
    return lookup_to_meta(sr.iter)
}
