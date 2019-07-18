package object

/*
#include "ccow.h"
*/
import "C"
import "unsafe"

import (
	"fmt"
	"os"
	"strings"

	"../efsutil"
	"../validate"
	"github.com/spf13/cobra"
)

const (
	ondemandPolicyLocal = C.ondemandPolicyLocal
	ondemandPolicyUnpin = C.ondemandPolicyUnpin
	ondemandPolicyPin = C.ondemandPolicyPin
	ondemandPolicyPersist = C.ondemandPolicyPersist
)

func setOndemandPolicy(path string, gen uint64, policy int) error {

	s := strings.SplitN(path, "/", 4)
	if len(s) < 4 {
		return fmt.Errorf("Invalid object path %v", path);
	}

	c_cluster := C.CString(s[0])
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(s[1])
	defer C.free(unsafe.Pointer(c_tenant))

	c_bucket := C.CString(s[2])
	defer C.free(unsafe.Pointer(c_bucket))

	c_object := C.CString(s[3])
	defer C.free(unsafe.Pointer(c_object))

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	var tc C.ccow_t

	ret := C.ccow_tenant_init(c_conf, c_cluster, C.strlen(c_cluster)+1,
		c_tenant, C.strlen(c_tenant)+1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_tenant_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	ret = C.ccow_ondemand_policy_change(tc, c_bucket, C.strlen(c_bucket)+1,
		c_object, C.strlen(c_object)+1, C.ulong(gen), C.ondemand_policy_t(policy));
	if ret != 0 {
		reason := "Unknown error code"
		if ret == -1 {
			reason = "Cannot change ondemand policy of a local object"
		} else if ret == -52 {
			reason = "Cannot change ondemand policy of a persistent object"
		} else if ret == -13 {
			reason = "the ondemand policy is set already"
		}
		return fmt.Errorf("%v (%d)", reason, ret)
	}
	return nil
}

var (
	pinCmd = &cobra.Command{
		Use:   "pin <cluster>/<tenant>/<bucket>/<object>",
		Short: "Pin a cacheable object",
		Long:  "Pin a cacheable object",
		Args:  validate.ObjectOnDemand,
		Run: func(cmd *cobra.Command, args []string) {
			err := setOndemandPolicy(args[0], 0, ondemandPolicyPin)
			if err != nil {
				fmt.Printf("ERROR: %v\n", err)
				os.Exit(1)
			}
		},
	}

	unpinCmd = &cobra.Command{
		Use:   "unpin <cluster>/<tenant>/<bucket>/<object>",
		Short: "Unpin a cacheable object",
		Long:  "Unpin a cacheable object",
		Args:  validate.ObjectOnDemand,
		Run: func(cmd *cobra.Command, args []string) {
			err := setOndemandPolicy(args[0], 0, ondemandPolicyUnpin)
			if err != nil {
				fmt.Printf("ERROR: %v\n", err)
				os.Exit(1)
			}
		},
	}

	persistCmd = &cobra.Command{
		Use:   "persist <cluster>/<tenant>/<bucket>/<object>",
		Short: "Persist a cacheable object",
		Long:  "Persist a cacheable object",
		Args:  validate.ObjectOnDemand,
		Run: func(cmd *cobra.Command, args []string) {
			err := setOndemandPolicy(args[0], 0, ondemandPolicyPersist)
			if err != nil {
				fmt.Printf("ERROR: %v\n", err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	ObjectCmd.AddCommand(pinCmd)
	ObjectCmd.AddCommand(unpinCmd)
	ObjectCmd.AddCommand(persistCmd)
}

