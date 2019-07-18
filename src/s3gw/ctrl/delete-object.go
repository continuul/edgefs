package ctrl

import "../app"
import "../ccow"

func DELETE_object (ctx *app.Context) error {
    bucket := ctx.Bucket
    object := ctx.Object

    tc, err := ccow.Connect(ctx.Cluster, ctx.Tenant)
    if err != nil { return err }
    defer tc.Release()

    _, err = tc.Get_Bucket_Meta(bucket)
    if err != nil { return err }

    err = tc.Delete_Object(bucket, object)

    return ctx.Empty(204)
}

func init () {
    app.Register("DELETE", "object", DELETE_object)
}
