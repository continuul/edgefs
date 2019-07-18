package app

import "net/http"
import "strings"

func set_plain_headers (ctx *Context, req *http.Request) {
    headers := map[string]string{}

    for k, v := range req.Header {
        headers[k] = strings.Join(v, ";")
    }

    ctx.Headers = headers
}

func subdomain_style_bucket (ctx *Context, req *http.Request) bool {
    domain := Config.Domain
    if domain == "" {
        return false
    }

    hosts := req.Header["host"]
    if hosts == nil {
        return false
    }
    host := hosts[0]
    dotdomain := "." + domain

    if strings.HasPrefix(host, "www.") {
        host = host[4:] /* emulate removeWWW from express.js */
    }

    if strings.HasSuffix(host, dotdomain) {
        ctx.Bucket = strings.TrimSuffix(host, dotdomain)
        ctx.Vhost = true;
    }

    return true
}

func set_context_query (ctx *Context, req *http.Request) {
    raw := req.URL.Query()
    query := map[string]string { }

    for k, v := range raw {
        query[k] = v[0]
    }

    ctx.Query = query
}

func parse_request_url (ctx *Context, req *http.Request) {
    var object, bucket, resource string

    path := req.URL.Path

    if path[0] == '/' {
        path = path[1:]
    }

    if subdomain_style_bucket(ctx, req) {
        object = path
    } else {
        slash := strings.IndexByte(path, '/')

        if slash >= 0 {
            bucket = path[0:slash]
            object = path[slash + 1:]
        } else {
            bucket = path
            object = ""
        }
    }

    /* resource string is used for error reporting */
    if bucket != "" && object != "" {
        resource = "/" + bucket + "/" + object
    } else if bucket != "" {
        resource = "/" + bucket
    } else {
        resource = "/"
    }

    ctx.Cluster = Config.Cluster_Name
    ctx.Tenant = Config.Tenant_Name
    ctx.Bucket = bucket
    ctx.Object = object
    ctx.Resource = resource
    ctx.Method = req.Method

    set_context_query(ctx, req)
}

func Parse_Request (req *http.Request, res http.ResponseWriter) (*Context) {
    var ctx Context

    ctx.req = req
    ctx.res = res
    ctx.finished = false

    set_plain_headers (&ctx, req)
    parse_request_url (&ctx, req)

    return &ctx
}
