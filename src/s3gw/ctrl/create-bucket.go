package ctrl

import "../app"
import "../ccow"

func PUT_bucket (ctx *app.Context) error {
    bucket := ctx.Bucket

    tc, err := ccow.Connect(ctx.Cluster, ctx.Tenant)
    if err != nil { return err }
    defer tc.Release()

    attrs, err := tc.Get_Bucket_Meta(bucket)
    if err == nil { return app.Error("BucketAlreadyExists") }

    err = tc.Create_Bucket(bucket)
    if err != nil { return err }

    attrs, err = tc.Get_Bucket_Meta(bucket)
    if err != nil { return err }

    name_hash_id := attrs.String("ccow-name-hash-id")
    if name_hash_id == "" { return app.Error("InternalError") }

    err = tc.Put_Empty_Object(bucket, name_hash_id)
    if err != nil { return err }

    return ctx.Empty(200)
}

func init () {
    app.Register("PUT", "bucket", PUT_bucket)
}
