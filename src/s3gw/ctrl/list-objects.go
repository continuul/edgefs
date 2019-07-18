package ctrl

import "log"
import "sort"
import "../app"
import "../ccow"

func list_all_objects (tc *ccow.Tenant, bucket, prefix string) (*ccow.List, error) {
    var all ccow.List
    var N int = 1000

    start := prefix
    preflen := len(prefix)

    for {
        part, err := tc.Get_List(bucket, "", start, N)

        if err != nil {
            if ccow.Not_Found(err) {
                break
            }
            return nil, err
        }

        n := len(*part)
        sort.Sort(*part)

        for _, p := range *part {
            if p.Key[0:preflen] != prefix {
                continue
            }
            all = append(all, p)
        }

        if n < N {
            break
        }

        last := (*part)[n-1].Key

        if last <= start {
            break
        }

        start = last
    }

    return &all, nil
}

func GET_bucket (ctx *app.Context) error {
    log.Println("GET-bucket")

    tc, err := ccow.Connect(ctx.Cluster, ctx.Tenant)
    if err != nil { return err }
    defer tc.Release()

    objects, err := list_all_objects(tc, ctx.Bucket, "")
    if err != nil { return err }

    xw := ctx.XML("ListBucketResult", true)
    xw.Tag("Bucket", ctx.Bucket)
    xw.Tag("Prefix", "")

    for _, p := range *objects {
        type Contents struct {
            Key string
            ETag string
            LastModified string
            Size uint64
            StorageClass string
        }

        xw.Encode(&Contents{
            Key: p.Key,
            ETag: "",
            LastModified: "-",
            Size: 0,
            StorageClass: "",
        })
    }

    xw.End()

    log.Println("done")

    return nil
}

func init () {
    app.Register("GET", "bucket", GET_bucket)
}
