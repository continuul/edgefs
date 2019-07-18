package ccow

/*
#include "ccow.h"
*/
import "C"
import "unsafe"
import "sync"
import "time"
import "io/ioutil"

const MAX_TENANT_REUSE uint = 10
const MAX_POOLED_PER_TENANT uint = 10
const TENANT_RELEASE_DELAY time.Duration = 5*1000*1000*1000 /* 5s in ns */

var Config *string

type Tenant struct { /* tenant context */
    c C.ccow_t
    cluster string
    tenant string
    used uint
}

/* "cluster-tenant" => sync.Pool[cached_tenant] */
var tenant_cache map[string](chan *Tenant)
var tenant_cache_mutex sync.RWMutex

func Read_Config (home string) {
    name := home + "/etc/ccow/ccow.json"
    buf, err := ioutil.ReadFile(name)
    if err != nil { panic(err) }

    str := string(buf)
    Config = &str
}

func tenant_init (cluster, tenant string) (*Tenant, error) {
    var tc Tenant

    c_config := C.CString(*Config)
    c_cluster := C.CString(cluster)
    c_tenant := C.CString(tenant)

    defer C.free(unsafe.Pointer(c_config))
    defer C.free(unsafe.Pointer(c_cluster))
    defer C.free(unsafe.Pointer(c_tenant))

    c_cluster_len := C.strlen(c_cluster) + 1
    c_tenant_len := C.strlen(c_tenant) + 1

    ret := C.ccow_tenant_init(c_config, c_cluster, c_cluster_len,
                                c_tenant, c_tenant_len, &tc.c)

    if ret != 0 {
        return nil, Error("ccow_tenant_init", ret)
    }

    tc.cluster = cluster
    tc.tenant = tenant
    tc.used = 0

    return &tc, nil
}

func Connect (cluster string, tenant string) (*Tenant, error) {
    key := cluster + "/" + tenant

    tenant_cache_mutex.RLock()
    pool, ok := tenant_cache[key]
    tenant_cache_mutex.RUnlock()

    if ok {
        select {
            case tc := <- pool:
                return tc, nil
            default:
        }
    }

    return tenant_init(cluster, tenant)
}

func wait_then_release (tc *Tenant) {
    time.Sleep(TENANT_RELEASE_DELAY)
    C.ccow_tenant_term(tc.c)
}

func (tc *Tenant) Release () {
    tc.used++

    if tc.used > MAX_TENANT_REUSE {
        go wait_then_release(tc)
        return
    }

    key := tc.cluster + "/" + tc.tenant

    /* Try read lock first, it is very likely to succeed. */
    tenant_cache_mutex.RLock()
    pool, ok := tenant_cache[key]
    tenant_cache_mutex.RUnlock()

    /* If not, re-check the key to avoid races in-between RUnlock and Lock */
    if !ok {
        tenant_cache_mutex.Lock()
        pool, ok = tenant_cache[key]
        if !ok {
            pool = make(chan *Tenant, MAX_POOLED_PER_TENANT)
            tenant_cache[key] = pool
        }
        tenant_cache_mutex.Unlock()
    }

    select {
        case pool <- tc:
        default: wait_then_release(tc)
    }
}

func init () {
    tenant_cache = make(map[string](chan *Tenant))
}
