package app

import "encoding/xml"

type XML_Writer struct {
    ctx *Context
    outer string
}

const xmlns string = "http://s3.amazonaws.com/doc/2006-03-01/"

func (ctx *Context) XML(tag string, needns bool) *XML_Writer {
    var xw XML_Writer

    ctx.Set("Content-Type", "application/xml")
    ctx.Write([]byte(xml.Header))

    if needns {
        ctx.Write([]byte("<" + tag + " xml:ns=\"" + xmlns + "\">\n"))
    } else {
        ctx.Write([]byte("<" + tag + ">\n"))
    }

    xw.ctx = ctx
    xw.outer = tag

    return &xw
}

func (xw *XML_Writer) Encode (v interface{}) {
    buf, err := xml.MarshalIndent(v, "  ", "  ")

    if err != nil { return }

    xw.ctx.Write(buf)
    xw.ctx.Write([]byte("\n"))
}

func (xw *XML_Writer) Tag (k, v string) {
    type Tag struct {
        XMLName xml.Name
        Value string `xml:",chardata"`
    }

    xw.Encode(&Tag{ xml.Name{ Local: k, Space: "" }, v })
}

func (xw *XML_Writer) End () {
    xw.ctx.Write([]byte("</" + xw.outer + ">\n"))
}
