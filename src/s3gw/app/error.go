package app

/*
#include <errno.h>
*/
import "C"
import "errors"
import "encoding/xml"

type AWSError struct {
    code string
}

type CcowError interface {
    Errno() int
}

var messages = map[string]string {
    "MalformedXMLError":    "Malformed XML",
    "InvalidRequest":       "Invalid request",
    "AccessDenied":         "Access denied",
    "InternalError":        "Internal error",
    "UnknownError":         "Unknown error",
    "BucketNotEmpty":       "The bucket you tried to delete is not empty",
    "BucketAlreadyExists":  "Bucket already exists",
};

var aws_to_http = map[string]int {
    "AccessDenied":        403,
    "NoSuchBucket":        404,
    "NoSuchKey":           404,
    "MethodNotAllowed":    405,
    "BucketNotEmpty":      409,
    "BucketAlreadyExists": 409,
    "InvalidRange":        416,
}

func aws_error_to_http (s3code string) int {
    if htcode, ok := aws_to_http[s3code]; ok {
        return htcode
    } else {
        return 400; /* blame everything on the client */
    }
}

func ccow_to_aws (ctx *Context, errno int) string {
    if errno == C.ENOENT {
        if ctx.Object == "" {
            return "NoSuchBucket"
        } else {
            return "NoSuchKey"
        }
    }

    return "InternalError"
}

func reply_error_xml(ctx *Context, code int, s3code, message string) {
    res := ctx.res

    type Error struct {
        Code string
        Message string
        Resource string
        RequestId string
    }

	body, err := xml.MarshalIndent(&Error{
		Code: s3code,
        Message: message,
        Resource: ctx.Resource,
        RequestId: ctx.id,
	}, "", "    ")

    if err != nil {
        body = []byte("Error while encoding error message\n")
        res.WriteHeader(500)
        res.Write(body)
        return
    }

    res.Header().Set("Content-Type", "application/xml")
    res.WriteHeader(code)
    res.Write([]byte(xml.Header))
    res.Write(body)
    res.Write([]byte("\n"))

    ctx.finished = true
}

func reply_error(ctx *Context, s3code string) error {
    htcode := aws_error_to_http(s3code)

    if msg, ok := messages[s3code]; ok {
        reply_error_xml(ctx, htcode, s3code, msg)
    } else {
        reply_error_xml(ctx, htcode, s3code, s3code)
    }

    return errors.New(s3code)
}

func Error(code string) error {
    return AWSError{ code }
}

func (e AWSError) Error() string {
    return e.code
}

func (ctx *Context) Finalize(err error) {
    if ctx.finished {
        return
    }
    if err == nil {
        return
    }

    if e, ok := err.(AWSError); ok {
        reply_error(ctx, e.code)
    } else if e, ok := err.(CcowError); ok {
        reply_error(ctx, ccow_to_aws(ctx, e.Errno()))
    } else {
        reply_error(ctx, "InternalError")
    }
}
