module github.com/Nexenta/edgefs/src/corosync-pod-watcher

go 1.12

require (
	github.com/Nexenta/edgefs/src/efscli v0.0.0
	k8s.io/apimachinery v0.0.0-20190612205821-1799e75a0719
	k8s.io/client-go v0.0.0-20190620085101-78d2af792bab
)

replace github.com/Nexenta/edgefs/src/efscli => ../efscli
