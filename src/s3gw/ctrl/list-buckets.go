package ctrl

import "log"
import "sort"
import "../app"
import "../ccow"

func list_all_buckets (tc *ccow.Tenant, prefix string) (*ccow.List, error) {
    var all ccow.List
    var N int = 1000

    start := prefix
    preflen := len(prefix)

    for {
        part, err := tc.Get_List("", "", start, N)

        if err != nil {
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

func GET_service (ctx *app.Context) error {
    log.Println("GET-service")

    tc, err := ccow.Connect(ctx.Cluster, ctx.Tenant)
    if err != nil { return err }
    defer tc.Release()

    buckets, err := list_all_buckets(tc, "")
    if err != nil { return err }

    xw := ctx.XML("ListAllMyBucketsResult", true)

    sort.Sort(buckets)

    for _, p := range *buckets {
        type Bucket struct {
            Name string
            CreationDate string
        }

        xw.Encode(&Bucket{ p.Key, "-" })
    }

    xw.End()

    log.Println("done")

    return nil
}

func init () {
    app.Register("GET", "service", GET_service)
}
