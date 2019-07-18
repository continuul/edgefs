package ctrl

import "log"
import "../app"
import "../ccow"

func read_chunk (ctx *app.Context, buf []byte) uint {
    got := uint(0)
    max := uint(len(buf))

    for {
        n, err := ctx.Read(buf[got:max])
        if n <= 0 { break }
        got = got + uint(n)
        if err != nil { break }
        if got >= max { break }
    }

    return got
}

func PUT_object (ctx *app.Context) error {
    log.Println("PUT-object /"+ctx.Bucket+"/"+ctx.Object)

    tc, err := ccow.Connect(ctx.Cluster, ctx.Tenant)
    if err != nil { return err }
    defer tc.Release()

    _, err = tc.Get_Bucket_Meta(ctx.Bucket)
    if err != nil { return err }

    sr, err := tc.Open_Write_Stream(ctx.Bucket, ctx.Object, 50000)
    if err != nil { return err }
    defer sr.Release()

    chunk_size := sr.Get_Default_Chunk_Size()
	err = sr.Set_Chunk_Size_Attr(chunk_size)
    if err != nil { return err }

	err = sr.Put_No_Data()
	if err != nil { return err }

    buf := make([]byte, chunk_size)
    off := uint64(0)

    for {
        n := read_chunk(ctx, buf)
        if n <= 0 { break }

        err = sr.Put_Chunk(buf[0:n], off)
        if err != nil { return err }

        off = off + uint64(n)
    }

    attrs, err := sr.Finalize()
    if err != nil { return err }

    if attrs != nil {
        content_hash := attrs.String("ccow-vm-content-hash-id")
        etag := attrs.String("ETag")

        if etag != "" {
            ctx.Set("ETag", "\"" + etag + "\"")
        } else if content_hash != "" {
            ctx.Set("ETag", "\"" + content_hash + "\"")
        }
    }

    //log.Println("done", off)
    return ctx.Empty(200) /* TODO */
}

func init () {
    app.Register("PUT", "object", PUT_object)
}
