package app

import "net/http"
import "strconv"

type Context struct {
    req *http.Request
    res http.ResponseWriter

    id string

    Cluster string
    Tenant string
    Method string
    Bucket string
    Object string
    Subresource string
    Resource string
    Query map[string]string
    Headers map[string]string
    Vhost bool

    finished bool
}

func (ctx *Context) Read(chunk []byte) (int, error) {
    return ctx.req.Body.Read(chunk)
}

func (ctx *Context) Set(key, val string) {
    ctx.res.Header().Set(key, val)
}

func (ctx *Context) Set_Uint(key string, val uint64) {
    ctx.res.Header().Set(key, strconv.FormatUint(val, 10))
}

func (ctx *Context) Empty(code int) error {
    ctx.res.WriteHeader(code)

    ctx.finished = true;

    return nil
}

func (ctx *Context) Write(chunk []byte) error {
    _, err := ctx.res.Write(chunk)

    ctx.finished = true;

    return err
}
