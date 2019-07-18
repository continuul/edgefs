package main

import "fmt"
import "time"
import "flag"
import "net/http"
import "log"
import "os"
import "strconv"

import "./app"
import "./auth"
import "./ccow"
import _ "./ctrl"

var cluster, tenant string
var port, sport int

func handle_request (w http.ResponseWriter, r *http.Request) {
    var err error = nil

    ctx := app.Parse_Request(r, w)

    err = app.Set_Request_Id(ctx)
    if err != nil { goto out }
    err = auth.Authenticate(ctx)
    if err != nil { goto out }
    err = auth.Check_Access(ctx)
    if err != nil { goto out }
    err = app.Route_Request(ctx)
    if err != nil { goto out }
out:
    ctx.Finalize(err)
}

type logWriter struct {
}

func (writer logWriter) Write(bytes []byte) (int, error) {
    return fmt.Print(time.Now().UTC().Format("2006-01-02T15:04:05.999Z") + " " + string(bytes))
}

func init() {
    flag.StringVar(&cluster, "cluster", "", "cluster name space")
    flag.StringVar(&tenant, "tenant", "", "tenant in the cluster")
    flag.IntVar(&port, "port", 0, "HTTP port to listen on")
    flag.IntVar(&sport, "sport", 0, "HTTPS port to listen on")
    flag.Parse()
}

func main() {
    log.SetFlags(0)
    log.SetOutput(new(logWriter))

    home := os.Getenv("NEDGE_HOME")
    if home == "" { home = "/opt/nedge" }

    app.Read_Config(home)
    ccow.Read_Config(home)

    if cluster != "" { app.Config.Cluster_Name = cluster }
    if tenant != "" { app.Config.Tenant_Name = tenant }
    if port != 0 { app.Config.Port = port }
    if sport != 0 { app.Config.Port_Secure = sport }

    log.Printf("Serving cluster=%s tenant=%s", app.Config.Cluster_Name, app.Config.Tenant_Name)

    address := ":" + strconv.Itoa(app.Config.Port)
    handler := http.HandlerFunc(handle_request)
    log.Fatal(http.ListenAndServe(address, handler))
}
