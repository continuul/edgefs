package main

import (
	"fmt"
	"os"
	"time"
	"regexp"
	"strings"
	"strconv"
	"io/ioutil"
	"os/exec"
	"math/rand"
	"flag"
	"github.com/Nexenta/edgefs/src/efscli/efsutil"
	 cliconfig "github.com/Nexenta/edgefs/src/efscli/config"
	 metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type corosyncNode struct {
	id uint32
	name string
	ip string
	online bool
	accCounter int
}


func updateCorosyncConfig(nodes string) error {
	// Create a temporary copy from the example file
	err := efsutil.CopyFile(nedgeHome+cliconfig.CorosyncConfIPv4ExampleFile, nedgeHome+CorosyncConfTmpFile)
	if err != nil {
		return fmt.Errorf("Can't copy corosync file %s to %s Error: %v \n", nedgeHome+cliconfig.CorosyncConfIPv4ExampleFile, nedgeHome+CorosyncConfTmpFile, err)
	}
	// Appned nodes list to the temporary file
	err = efsutil.AppendStringToFile(nedgeHome+CorosyncConfTmpFile, nodes)
	if err != nil {
		return fmt.Errorf("Can't aapend nodes config to corosync file %s Error: %v\n",nedgeHome+CorosyncConfTmpFile, err)
	}

	input, err := ioutil.ReadFile(nedgeHome + CorosyncConfTmpFile)
	if err != nil {
		return fmt.Errorf("Can't read a temp corosync file %s Error: %v\n",nedgeHome+CorosyncConfTmpFile, err)
	}

	// adjust log file location
	output := regexp.MustCompile(`/opt/nedge`).ReplaceAllString(string(input), os.Getenv("NEDGE_HOME"))
	var ccowdConf cliconfig.CcowdConf

	err = efsutil.LoadJsonFile(&ccowdConf, nedgeHome + cliconfig.CCOWDJsonFile)
	if err != nil {
		return fmt.Errorf("ccowd.json: Error: %v\n", err)
	}

	// adjust netmtu to the current value of selected server interface name
	ifname0 := strings.Split(ccowdConf.Network.ServerInterfaces, ";")[0]
	netmtu := cliconfig.DetectMTU(ifname0)
	output = regexp.MustCompile(`netmtu:.*`).ReplaceAllString(output, "netmtu: "+strconv.Itoa(netmtu))
	// Update the temporary file with recent changes
	if err = ioutil.WriteFile(nedgeHome+CorosyncConfTmpFile, []byte(output), 0666); err != nil {
		return fmt.Errorf("%v write: Error: %v\n", nedgeHome+CorosyncConfTmpFile, err)
	}
	// Replace the corosync.conf with newly create file
	return os.Rename(nedgeHome+CorosyncConfTmpFile, nedgeHome+cliconfig.CorosyncConfFile)
}

func CorosyncRun() {
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		fmt.Printf("ERROR: couldn't create k8s client: %v\n", err)
		os.Exit(1)
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	if _, err := regexp.Compile(targetTpl); err != nil {
		panic(err.Error())
	}
	// Prepare a target pod name template validator
	valid := regexp.MustCompile(targetTpl)
	pmap := make(map[string]*corosyncNode)

	for loopCnt, cfgChanged := 1, 0; true; loopCnt++ {
		// Fetch all pods from the edgefs' namespace
		pods, err := clientset.CoreV1().Pods(namespace).List(metav1.ListOptions{})
		if err != nil {
			fmt.Printf("ERROR getting pods for namespace %v: %v\n", namespace, err)
			time.Sleep(time.Duration(loopDelay) * time.Second)
			continue
		}
		for _,item := range(pods.Items) {
			if valid.Match([]byte(item.Name)) {
				if pod, ok := pmap[item.Name]; ok {
					if len(item.Status.PodIP) != 0 {
						// Pod exists, make sure IP hasn't been changed
						if pod.online != true {
							pod.online = true
							cfgChanged = loopCnt
							fmt.Printf("POD online: name: %v, node: %v, ip: %v\n", item.Name, item.Spec.NodeName, item.Status.PodIP)
						}
						if pod.ip != item.Status.PodIP {
							fmt.Printf("POD IP changed: name: %v, node: %v, ip: %v, ip old: %v\n", item.Name, item.Spec.NodeName, item.Status.PodIP, pod.ip)
							pod.ip = item.Status.PodIP
							cfgChanged = loopCnt
						}
					}
					pod.accCounter = loopCnt
				} else if len(item.Status.PodIP) != 0 {
					// New pod
					pmap[item.Name] = &corosyncNode {
						id: efsutil.GetMD5HashInt32(item.Name + namespace),
						name: item.Name,
						ip: item.Status.PodIP,
						online: true,
						accCounter: loopCnt,
					}
					fmt.Printf("New POD: name: %v, node: %v, ip: %v\n", item.Name, item.Spec.NodeName, item.Status.PodIP)
					cfgChanged = loopCnt
				}
			}
		}
		// Clear online flag for POD which hasn't been found during last pods iteration
		for _, pod := range(pmap) {
			if pod.accCounter != loopCnt && pod.online {
				pod.online = false
				fmt.Printf("POD offline: name: %v, ip: %v\n", pod.name, pod.ip)
				pod.accCounter = loopCnt
			}
		}
		if cfgChanged != 0  && (loopCnt - cfgChanged)*loopDelay >= backoffDelay {
			var nodeList strings.Builder
			nodeList.WriteString("\nnodelist {\n")
			for _, pod := range(pmap) {
				if pod.online {
					nodeList.WriteString("  node {\n")
					nodeList.WriteString("    ring0_addr: " + pod.ip + "\n")
					nodeList.WriteString("    nodeid: " + fmt.Sprint(pod.id) + "\n")
					nodeList.WriteString("  }\n")
				}
			}
			nodeList.WriteString("}\n")
			// Prevent simultaneous corosycn config reload by randomizing intervals
			time.Sleep(time.Duration((1 + rand.Intn(len(pmap))))* time.Second)
			fmt.Printf("corosync config update:\n%v\n", nodeList.String())
			err := updateCorosyncConfig(nodeList.String())
			if err != nil {
				fmt.Printf("updateCorosyncConfig error: %v\n", err)
			} else {
				err = exec.Command(nedgeHome+"/sbin/corosync-cfgtool", "-R").Run()
				if err != nil {
					fmt.Printf("corosync-cfgtool error: %v\n", err)
				}
			}
			cfgChanged = 0;
		}
		time.Sleep(time.Duration(loopDelay) * time.Second)
	}
}


var (
	namespace string = "rook-edgefs"
	targetTpl string = ""
	CorosyncConfTmpFile = "/etc/corosync/corosync.conf.tmp"
	loopDelay int = 5
	backoffDelay int = 15
	nedgeHome = "/opt/nedge"
)


func main() {
	flag.IntVar(&loopDelay, "i", 5, "Pods poll interval, sec")
	flag.IntVar(&backoffDelay, "b", 15, "Corosync re-configuration backoff time, sec")
	flag.StringVar(&namespace, "n", "", "Namespace the targets run in. Default: rook-edgefs")
	flag.StringVar(&targetTpl, "t", "rook-edgefs-target-.*", "Target name template. Default: rook-edgefs-target-.*")
	flag.Parse()
	nedgeHome = os.Getenv("NEDGE_HOME")
	if len(nedgeHome) == 0 {
		nedgeHome = "/opt/nedge"
	}
	if len(namespace) == 0 {
		namespace = os.Getenv("K8S_NAMESPACE")
	}
	if len(namespace) == 0 {
		namespace = "rook-edgefs"
	}
	CorosyncRun()
}
