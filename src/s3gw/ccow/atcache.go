package ccow

import "time"
import "sync"
import "../app"

const CACHE_TIME time.Duration = 5*60

type cache_meta_record struct {
    ts time.Time
    attrs *Meta
}

var cached_attrs map[string]cache_meta_record
var cached_attrs_mutex sync.RWMutex

func get_cached_meta (key string) (*Meta) {
    now := time.Now()

    cached_attrs_mutex.RLock()

    rec, ok := cached_attrs[key]

    cached_attrs_mutex.RUnlock()

    if !ok {
        return nil
    }

    if now.Sub(rec.ts) >= CACHE_TIME {
        delete(cached_attrs, key)
        return nil
    }

    return rec.attrs
}

func set_cached_meta (key string, attrs *Meta) {
    now := time.Now()

    cached_attrs_mutex.Lock()

    cached_attrs[key] = cache_meta_record { now, attrs }

    cached_attrs_mutex.Unlock()
}

func Get_Object_Meta (tc *Tenant, bucket, object string) (*Meta, error) {
    key := tc.cluster + "/" + tc.tenant + "/" + bucket + "/" + object
    attrs := get_cached_meta(key)

    if attrs != nil {
        return attrs, nil
    }

    attrs, err := tc.Get_Meta(bucket, object)

    if err != nil {
        return nil, err
    }

    set_cached_meta(key, attrs)

    return attrs, nil
}

func (tc *Tenant) Get_Bucket_Meta (bucket string) (*Meta, error) {
    key := tc.cluster + "/" + tc.tenant + "/" + bucket
    attrs := get_cached_meta(key)

    if attrs != nil {
        return attrs, nil
    }

    attrs, err := tc.Get_Meta(bucket, "")

    if err != nil {
        if Not_Found(err) {
            return nil, app.Error("NoSuchBucket")
        } else {
            return nil, err
        }
    }

    return attrs, nil
}

func (tc *Tenant) flush_bucket (bucket string) {
    key := tc.cluster + "/" + tc.tenant + "/" + bucket

    cached_attrs_mutex.Lock()

    delete(cached_attrs, key)

    cached_attrs_mutex.Unlock()
}

func (tc *Tenant) flush_object (bucket, object string) {
    key := tc.cluster + "/" + tc.tenant + "/" + bucket + "/" + object

    cached_attrs_mutex.Lock()

    delete(cached_attrs, key)

    cached_attrs_mutex.Unlock()
}

func init () {
    cached_attrs = make(map[string]cache_meta_record)
}
