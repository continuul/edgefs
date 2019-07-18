package ctrl

import "log"
import "../app"
import "../ccow"

func set_object_headers (ctx *app.Context, attrs *ccow.Meta) {
    logical_size := attrs.Uint64("ccow-logical-size")
    content_type := attrs.String("content-type")
    content_hash := attrs.String("ccow-vm-content-hash-id")
    etag := attrs.String("ETag")

    ctx.Set_Uint("Content-Length", logical_size)

    if content_type != "" {
        ctx.Set("Content-Type", content_type)
    } else {
        ctx.Set("Content-Type", "application/octet-stream")
    }
    if etag != "" {
        ctx.Set("ETag", "\"" + etag + "\"")
    } else if content_hash != "" {
        ctx.Set("Etag", "\"" + content_hash + "\"")
    }
}

func GET_object (ctx *app.Context) error {
    log.Println("GET-object /"+ctx.Bucket+"/"+ctx.Object)

    tc, err := ccow.Connect(ctx.Cluster, ctx.Tenant)
    if err != nil { return err }
    defer tc.Release()

    _, err = tc.Get_Bucket_Meta(ctx.Bucket)
    if err != nil { return err }

    sr, err := tc.Open_Read_Stream(ctx.Bucket, ctx.Object, 50000)
    if err != nil { return err }
    defer sr.Release()

	if !sr.Object_Exists() {
        return app.Error("NoSuchKey")
    }

    attrs := sr.Get_Meta()
    set_object_headers(ctx, attrs)

    chunk_size := attrs.Uint("ccow-chunkmap-chunk-size")
    logical_size := attrs.Uint64("ccow-logical-size")

    //if chunk_size == 0 {
    //    chunk_size := sr.Get_Default_Chunk_Size()
    //}

    buf := make([]byte, chunk_size)
    off := uint64(0)
    run := chunk_size

    for {
        if off >= logical_size {
            break
        }
        if off + uint64(run) > logical_size {
            run = uint(logical_size - off)
            buf = buf[0:run]
        }

        err := sr.Get_Chunk(buf, off)
        if err != nil { return err }

        err = ctx.Write(buf)
        if err != nil { return err }

        off += uint64(run)
    }

    sr.Stop()

    return nil
}

func init () {
    app.Register("GET", "object", GET_object)
}
