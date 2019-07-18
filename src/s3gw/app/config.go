package app

import (
    "os"
    "io/ioutil"
    "encoding/json"
)

var Config struct {
    Port int `json:"port"`
    Port_Secure int `json:"port_secure"`
    Chunk_Size int `json:"chunk_size"`
    Cluster_Name string `json:"cluster_name"`
    Iovarr_Size int `json:"iovarr_size"`
    Tenant_Name string `json:"tenant_name"`
    Number_of_versions int `json:"number_of_versions"`
    Debug bool `json:"debug"`
    No_Cleanup bool `json:"no_cleanup"`
    Need_MD5 bool `json:"need_md5"`
    Region string `json:"region"`
    Domain string `json:"domain"`
}

func Read_Config (home string) {
    confname := home + "/etc/ccow/s3gw.json"
    rawjson, err := ioutil.ReadFile(confname)
    if err != nil {
        if _, err := os.Stat(confname + ".example"); os.IsNotExist(err) { panic(err) }
        data, err := ioutil.ReadFile(confname + ".example")
        if err != nil { panic(err) }
        err = ioutil.WriteFile(confname, data, 0644)
        if err != nil { panic(err) }
        rawjson, err = ioutil.ReadFile(confname)
        if err != nil { panic(err) }
    }

    err = json.Unmarshal(rawjson, &Config)
    if err != nil { panic(err) }
}
