package config

import (
	"fmt"
	"github.com/google/uuid"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

var (
	isNBD = regexp.MustCompile("^nbd[0-9]+p?[0-9]{0,}$")
	debug = false
)

const (
	DiskType  = "disk"
	SSDType   = "ssd"
	PartType  = "part"
	DMPartType = "md"
	CryptType = "crypt"
	LVMType   = "lvm"
	sgdisk    = "sgdisk"
	mountCmd  = "mount"
)

type Partition struct {
	Name       string
	Size       uint64
	Label      string
	Filesystem string
	MountPoint string
}

// LocalDevice contains information about an unformatted block device
type LocalDisk struct {
	// Name is the device name
	Name string `json:"name"`
	// Parent is the device parent's name
	Parent string `json:"parent"`
	// HasChildren is whether the device has a children device
	HasChildren bool `json:"hasChildren"`
	// DevLinks is the persistent device path on the host
	DevLinks string `json:"devLinks"`
	// Size is the device capacity in byte
	Size uint64 `json:"size"`
	// UUID is used by /dev/disk/by-uuid
	UUID string `json:"uuid"`
	// Serial is the disk serial used by /dev/disk/by-id
	Serial string `json:"serial"`
	// Type is disk type
	Type string `json:"type"`
	// Rotational is the boolean whether the device is rotational: true for hdd, false for ssd and nvme
	Rotational bool `json:"rotational"`
	// ReadOnly is the boolean whether the device is readonly
	Readonly bool `json:"readOnly"`
	// Partitions is a partition slice
	Partitions []Partition
	// Filesystem is the filesystem currently on the device
	Filesystem string `json:"filesystem"`
	// Vendor is the device vendor
	Vendor string `json:"vendor"`
	// Model is the device model
	Model string `json:"model"`
	// WWN is the world wide name of the device
	WWN string `json:"wwn"`
	// WWNVendorExtension is the WWN_VENDOR_EXTENSION from udev info
	WWNVendorExtension string `json:"wwnVendorExtension"`
	// Empty checks whether the device is completely empty
	Empty bool `json:"empty"`
}

func ListDevices() ([]string, error) {
	devices, err := exec.Command("lsblk", "--all", "--noheadings", "--list", "--output", "KNAME").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list all devices: %+v", err)
	}

	return strings.Split(string(devices), "\n"), nil
}

func GetDevicePartitions(device string) (partitions []Partition, unusedSpace uint64, err error) {
	output, err := exec.Command("lsblk", fmt.Sprintf("/dev/%s", device),
		"--bytes", "--pairs", "--output", "NAME,SIZE,TYPE,PKNAME,MOUNTPOINT").Output()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get device %s partitions. %+v", device, err)
	}
	partInfo := strings.Split(string(output), "\n")
	var deviceSize uint64
	var totalPartitionSize uint64
	for _, info := range partInfo {
		props := parseKeyValuePairString(info)
		name := props["NAME"]
		if name == device {
			// found the main device
			deviceSize, err = strconv.ParseUint(props["SIZE"], 10, 64)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to get device %s size. %+v", device, err)
			}
		} else if props["PKNAME"] == device &&
			(props["TYPE"] == PartType || props["TYPE"] == DMPartType) {
			// found a partition
			p := Partition{Name: name}
			p.Size, err = strconv.ParseUint(props["SIZE"], 10, 64)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to get partition %s size. %+v", name, err)
			}
			totalPartitionSize += p.Size
			if v, ok := props["MOUNTPOINT"]; ok {
				p.MountPoint = v
			}

			info, err := GetUdevInfo(name)
			if err != nil {
				return nil, 0, err
			}
			if v, ok := info["ID_PART_ENTRY_NAME"]; ok {
				p.Label = v
			}
			if v, ok := info["PARTNAME"]; ok {
				p.Label = v
			}
			if v, ok := info["ID_FS_TYPE"]; ok {
				p.Filesystem = v
			}
			partitions = append(partitions, p)
		}
	}

	if deviceSize > 0 {
		unusedSpace = deviceSize - totalPartitionSize
	}
	return partitions, unusedSpace, nil
}

func GetAvailableDevices(devices []*LocalDisk) []string {

	var available []string
	for _, device := range devices {
		if debug {
			fmt.Printf("Evaluating device %+v\n", device)
		}
		if GetDeviceEmpty(device) {
			if debug {
				fmt.Printf("Available device: %s\n", device.Name)
			}
			available = append(available, device.Name)
		}
	}

	return available
}

// check whether a device is completely empty
func GetDeviceEmpty(device *LocalDisk) bool {
	return device.Parent == "" && (device.Type == DiskType || device.Type == SSDType || device.Type == CryptType || device.Type == LVMType) && len(device.Partitions) == 0 && device.Filesystem == ""
}

func GetDevicePropertiesFromPath(devicePath string) (map[string]string, error) {
	output, err := exec.Command("lsblk", devicePath,
		"--bytes", "--nodeps", "--pairs", "--output", "SIZE,ROTA,RO,TYPE,PKNAME").Output()
	if err != nil {
		// try to get more information about the command error
		if exitError, ok := err.(*exec.ExitError); ok {
			ws := exitError.Sys().(syscall.WaitStatus)
			if ok && ws.ExitStatus() == 32 {
				// certain device types (such as loop) return exit status 32 when probed further,
				// ignore and continue without logging
				return map[string]string{}, nil
			}
		}

		return nil, err
	}

	return parseKeyValuePairString(string(output)), nil
}

func GetDeviceProperties(device string) (map[string]string, error) {
	return GetDevicePropertiesFromPath(fmt.Sprintf("/dev/%s", device))
}

// look up the UUID for a disk.
func GetDiskUUID(device string) (string, error) {
	output, err := exec.Command(sgdisk, "--print", fmt.Sprintf("/dev/%s", device)).Output()
	if err != nil {
		return "", err
	}

	return parseUUID(device, string(output))
}
// Discover all the details of devices available on the local node
func DiscoverDevices() ([]*LocalDisk, error) {
	return DiscoverDevicesPred(nil)
}

// Discover all the details of devices available on the local node
// The predicate used to filter out unwanted entries
func DiscoverDevicesPred(pred func(*LocalDisk) bool) ([]*LocalDisk, error) {

	var disks []*LocalDisk
	devices, err := ListDevices()
	if err != nil {
		return nil, err
	}

	for _, d := range devices {

		if ignoreDevice(d) {
			// skip device
			continue
		}

		diskProps, err := GetDeviceProperties(d)
		if err != nil {
			if debug {
				fmt.Printf("skipping device %s: %+v\n", d, err)
			}
			continue
		}

		diskType, ok := diskProps["TYPE"]
		if pred == nil && (!ok || (diskType != SSDType && diskType != CryptType && diskType != DiskType && diskType != PartType)) {
			// unsupported disk type or it will be cheked later in this function
			continue
		}

		// get the UUID for disks
		var diskUUID string
		if diskType != PartType {
			diskUUID, err = GetDiskUUID(d)
			if err != nil {
				if debug {
					fmt.Printf("skipping device %s with an unknown uuid. %+v\n", d, err)
				}
				continue
			}
		}

		udevInfo, err := GetUdevInfo(d)
		if err != nil {
			if debug {
				fmt.Printf("failed to get udev info for device %s: %+v\n", d, err)
			}
			continue
		}

		disk := &LocalDisk{Name: d, UUID: diskUUID}

		if val, ok := diskProps["TYPE"]; ok {
			disk.Type = val
		}
		if val, ok := diskProps["SIZE"]; ok {
			if size, err := strconv.ParseUint(val, 10, 64); err == nil {
				disk.Size = size
			}
		}
		if val, ok := diskProps["ROTA"]; ok {
			if rotates, err := strconv.ParseBool(val); err == nil {
				disk.Rotational = rotates
			}
		}
		if val, ok := diskProps["RO"]; ok {
			if ro, err := strconv.ParseBool(val); err == nil {
				disk.Readonly = ro
			}
		}
		if val, ok := diskProps["PKNAME"]; ok {
			disk.Parent = strings.TrimSpace(val)
		}

		// parse udev info output
		if val, ok := udevInfo["DEVLINKS"]; ok {
			disk.DevLinks = val
		}
		if val, ok := udevInfo["ID_FS_TYPE"]; ok {
			disk.Filesystem = val
		}
		if val, ok := udevInfo["ID_SERIAL"]; ok {
			disk.Serial = val
		}

		if val, ok := udevInfo["ID_VENDOR"]; ok {
			disk.Vendor = val
		}

		if val, ok := udevInfo["ID_MODEL"]; ok {
			disk.Model = val
		}

		if val, ok := udevInfo["ID_WWN_WITH_EXTENSION"]; ok {
			disk.WWNVendorExtension = val
		}

		if val, ok := udevInfo["ID_WWN"]; ok {
			disk.WWN = val
		}
		if pred == nil || pred(disk) {
			disks = append(disks, disk)
		}
	}

	return disks, nil
}

// get the file systems availab
func GetDeviceFilesystems(device string) (string, error) {
	output, err := exec.Command("udevadm", "info", "--query=property", fmt.Sprintf("/dev/%s", device)).Output()
	if err != nil {
		return "", fmt.Errorf("command udevadm info failed: %+v", err)
	}

	return parseFS(string(output)), nil
}

func DetectLocalDisks() (disks []LocalDisk, err error) {
	return disks, nil
}

func GetUdevInfo(device string) (map[string]string, error) {
	output, err := exec.Command("udevadm", "info", "--query=property", fmt.Sprintf("/dev/%s", device)).Output()
	if err != nil {
		return nil, err
	}

	return parseUdevInfo(string(output)), nil
}

func ProbeDevices(verbose bool) ([]LocalDisk, error) {

	debug = verbose

	devices := make([]LocalDisk, 0)
	localDevices, err := DiscoverDevices()
	if err != nil {
		return devices, fmt.Errorf("failed initial hardware discovery. %+v", err)
	}
	for _, device := range localDevices {
		if device == nil {
			continue
		}
		if device.Type == PartType {
			continue
		}

		partitions, _, err := GetDevicePartitions(device.Name)
		if err != nil {
			if debug {
				fmt.Printf("failed to check device partitions %s: %v\n", device.Name, err)
			}
			continue
		}

		// check if there is a file system on the device
		fs, err := GetDeviceFilesystems(device.Name)
		if err != nil {
			if debug {
				fmt.Printf("failed to check device filesystem %s: %v\n", device.Name, err)
			}
			continue
		}
		device.Partitions = partitions
		device.Filesystem = fs
		device.Empty = GetDeviceEmpty(device)

		devices = append(devices, *device)
	}

	if debug {
		fmt.Printf("available devices: %+v\n", devices)
	}
	return devices, nil
}

func ignoreDevice(d string) bool {
	return isNBD.MatchString(d)
}

// converts a raw key value pair string into a map of key value pairs
// example raw string of `foo="0" bar="1" baz="biz"` is returned as:
// map[string]string{"foo":"0", "bar":"1", "baz":"biz"}
func parseKeyValuePairString(propsRaw string) map[string]string {
	// first split the single raw string on spaces and initialize a map of
	// a length equal to the number of pairs
	props := strings.Split(propsRaw, " ")
	propMap := make(map[string]string, len(props))

	for _, kvpRaw := range props {
		// split each individual key value pair on the equals sign
		kvp := strings.Split(kvpRaw, "=")
		if len(kvp) == 2 {
			// first element is the final key, second element is the final value
			// (don't forget to remove surrounding quotes from the value)
			propMap[kvp[0]] = strings.Replace(kvp[1], `"`, "", -1)
		}
	}

	return propMap
}

func parseUdevInfo(output string) map[string]string {
	lines := strings.Split(output, "\n")
	result := make(map[string]string, len(lines))
	for _, v := range lines {
		pairs := strings.Split(v, "=")
		if len(pairs) > 1 {
			result[pairs[0]] = pairs[1]
		}
	}
	return result
}

// finds the disk uuid in the output of sgdisk
func parseUUID(device, output string) (string, error) {

	// find the line with the uuid
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Index(line, "Disk identifier (GUID)") != -1 {
			words := strings.Split(line, " ")
			for _, word := range words {
				// we expect most words in the line not to be a uuid, but will return the first one that is
				result, err := uuid.Parse(word)
				if err == nil {
					return result.String(), nil
				}
			}
		}
	}

	return "", fmt.Errorf("uuid not found for device %s. output=%s", device, output)
}

// find fs from udevadm info
func parseFS(output string) string {
	m := parseUdevInfo(output)
	if v, ok := m["ID_FS_TYPE"]; ok {
		return v
	}
	return ""
}
