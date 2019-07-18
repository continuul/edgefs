package app

type Controller func(*Context)error

var Routes map[string]Controller
var Supported map[string]bool

func Register(method, resource string, handler Controller) {
    key := method + "-" + resource

    if _, ok := Routes[key]; ok {
        panic("duplicate routing for" + key)
    }

    Routes[key] = handler
    Supported[resource] = true
}

func Route_Request (ctx *Context) error {
    var stem string

    if ctx.Headers["x-amz-copy-source"] != "" {
        stem = "copysrc"

        if ctx.Method != "PUT" {
            return Error("MethodNotSupported")
        }
        if ctx.Subresource == "uploadId" {
            stem = stem + "-uploadId"
        } else if ctx.Subresource != "" {
            return Error("InvalidRequest")
        }
    } else {
        if ctx.Object != "" {
            stem = "object"
        } else if ctx.Bucket != "" {
            stem = "bucket"
        } else {
            stem = "service"
        }

        if ctx.Subresource != "" {
            stem = stem + "-" + ctx.Subresource

            if comp, ok := ctx.Query["comp"]; ok {
                stem = stem + "-" + comp
            }
        }
    }

    key := ctx.Method + "-" + stem

    if handler, ok := Routes[key]; ok {
        return handler(ctx)
    }

    if !Supported[stem] {
        return Error("UnknownResource")
    } else {
        return Error("MethodNotSupported")
    }
}

func init() {
    Routes = make(map[string]Controller)
    Supported = make(map[string]bool)
}
