package config

import (
	"fmt"
	"strings"
)

type RTDevice struct {
	Name              string `json:"name,omitempty"`
	Device            string `json:"device,omitempty"`
	Psize             int    `json:"psize,omitempty"`
	MdcacheReserved   int    `json:"mdcache_reserved,omitempty"`
	HddReadahead      int    `json:"hdd_readahead,omitempty"`
	VerifyChid        int    `json:"verify_chid"`
	Journal           string `json:"journal,omitempty"`
	Metadata          string `json:"metadata,omitempty"`
	Bcache            int    `json:"bcache,omitempty"`
	BcacheWritearound int    `json:"bcache_writearound"`
	PlevelOverride    int    `json:"plevel_override,omitempty"`
	Sync              int    `json:"sync"`
	Detached          int    `json:"detached"`
}

type RTDevices struct {
	Devices []RTDevice `json:"devices,omitempty"`
}

type RTDeviceParams struct {
	MDReserved         int    // override default 60%
	HDDReadAhead       int    // override default 256k
	DisableVerifyChid  bool   // force RtVerifyChid be 0
	NoSync             bool   // force Sync be 0
	RtVerifyChid       int    // 0 (disabled), 1 (verify on write) or 2(verify on read/write)
	LmdbPageSize       int    // 4096, 8192, 16384 or 32768
	MaxSizeGB          uint64 // 0 (use all available capacity), in gigabytes
	UseBcache          bool   // enable bcache
	UseBcacheWB        bool   // enable write back cache
	UseMetadataMask    string // what guts needs to go to SSD and what not
	UseMetadataOffload bool   // when useAllSSD is false, enable metadata offload on SSD
	UseAllSSD          bool   // only look for SSD/NVMe
	RtPlevelOverride   int    // if > 0, override automatic partitioning numbering logic
	Sync               int
}

func DefaultRTParams() (params *RTDeviceParams) {
	return &RTDeviceParams{
		MDReserved:         0,
		HDDReadAhead:       0,
		DisableVerifyChid:  false,
		NoSync:             false,
		RtVerifyChid:       1,
		LmdbPageSize:       16384,
		MaxSizeGB:          0,
		UseBcache:          false,
		UseBcacheWB:        false,
		UseMetadataMask:    "0xff",
		UseMetadataOffload: false,
		UseAllSSD:          false,
		RtPlevelOverride:   0,
		Sync:               1,
	}
}

func getIdDevLinkName(dls string) (dl string) {
	dlsArr := strings.Split(dls, " ")
	for i := range dlsArr {
		s := strings.Replace(dlsArr[i], "/dev/disk/by-id/", "", 1)
		if strings.Contains(s, "/") || strings.Contains(s, "wwn-") {
			continue
		}
		dl = s
		break
	}
	return dl
}

func GetRTDevices(nodeDisks []LocalDisk, rtParams *RTDeviceParams) (rtDevices []RTDevice, err error) {

	if rtParams == nil {
		rtParams = DefaultRTParams()
	}

	var ssds []LocalDisk
	var hdds []LocalDisk
	var devices []LocalDisk

	for i := range nodeDisks {
		if !nodeDisks[i].Empty || len(nodeDisks[i].Partitions) > 0 {
			continue
		}
		if nodeDisks[i].Rotational {
			hdds = append(hdds, nodeDisks[i])
		} else {
			ssds = append(ssds, nodeDisks[i])
		}
		devices = append(devices, nodeDisks[i])
	}

	//var rtdevs []RTDevice
	if rtParams.UseAllSSD {
		//
		// All flush media case (High Performance)
		//
		if len(ssds) == 0 {
			return rtDevices, fmt.Errorf("No SSD/NVMe media found")
		}
		if rtParams.UseMetadataOffload {
			fmt.Println("Warning: useMetadataOffload parameter is ignored due to use useAllSSD=true")
		}

		for i := range devices {
			if devices[i].Rotational {
				continue
			}
			rtdev := RTDevice{
				Name:       getIdDevLinkName(devices[i].DevLinks),
				Device:     "/dev/" + devices[i].Name,
				Psize:      rtParams.LmdbPageSize,
				VerifyChid: rtParams.RtVerifyChid,
				Sync:       rtParams.Sync,
			}
			if rtParams.RtPlevelOverride != 0 {
				rtdev.PlevelOverride = rtParams.RtPlevelOverride
			}
			rtDevices = append(rtDevices, rtdev)
		}
		return rtDevices, nil
	}

	if len(hdds) == 0 {
		return rtDevices, fmt.Errorf("No HDD media found")
	}

	if !rtParams.UseMetadataOffload {
		//
		// All HDD media case (capacity, cold archive)
		//
		for i := range devices {
			if !devices[i].Rotational {
				continue
			}
			rtdev := RTDevice{
				Name:       getIdDevLinkName(devices[i].DevLinks),
				Device:     "/dev/" + devices[i].Name,
				Psize:      rtParams.LmdbPageSize,
				VerifyChid: rtParams.RtVerifyChid,
				Sync:       rtParams.Sync,
			}
			if rtParams.RtPlevelOverride != 0 {
				rtdev.PlevelOverride = rtParams.RtPlevelOverride
			}
			if rtParams.HDDReadAhead != 0 {
				rtdev.HddReadahead = rtParams.HDDReadAhead
			}
			rtDevices = append(rtDevices, rtdev)
		}
		return rtDevices, nil
	}

	//
	// Hybrid SSD/HDD media case (optimal)
	//
	if len(hdds) < len(ssds) || len(ssds) == 0 {
		return rtDevices, fmt.Errorf("Confusing use of useMetadataOffload parameter HDDs(%d) < SSDs(%d)\n", len(hdds), len(ssds))
	}


	var hdds_divided [][]LocalDisk
	for i := len(ssds); i > 0; i-- {
		chunkSize := len(hdds) / i
		mod := len(hdds) % i
		if mod > 0 {
			chunkSize++
		}

		if len(hdds) < chunkSize {
			chunkSize = len(hdds)
		}
		hdds_divided = append(hdds_divided, hdds[:chunkSize])
		hdds = hdds[chunkSize:]
	}

	for i := range hdds_divided {
		for j := range hdds_divided[i] {
			rtdev := RTDevice{
				Name:       getIdDevLinkName(hdds_divided[i][j].DevLinks),
				Device:     "/dev/" + hdds_divided[i][j].Name,
				Psize:      rtParams.LmdbPageSize,
				VerifyChid: rtParams.RtVerifyChid,
				Journal:    getIdDevLinkName(ssds[i].DevLinks),
				Metadata:   getIdDevLinkName(ssds[i].DevLinks) + "," + rtParams.UseMetadataMask,
				Sync:       rtParams.Sync,
			}
			if rtParams.UseBcache {
				rtdev.Bcache = 1
			}
			if rtParams.UseBcacheWB {
				rtdev.BcacheWritearound = 0
			} else {
				rtdev.BcacheWritearound = 1
			}
			if rtParams.MDReserved != 0 {
				rtdev.MdcacheReserved = rtParams.MDReserved
			}
			if rtParams.HDDReadAhead != 0 {
				rtdev.HddReadahead = rtParams.HDDReadAhead
			}
			if rtParams.RtPlevelOverride != 0 {
				rtdev.PlevelOverride = rtParams.RtPlevelOverride
			}
			rtDevices = append(rtDevices, rtdev)
		}
	}
	return rtDevices, nil
}
