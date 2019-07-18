# EdgeFS - a multi-cloud scalable distributed storage system

EdgeFS is high-performance and low-latency object storage system released under Apache License v2.0 developed in C/Go.
It provides Kubernetes integrated Multi-Head Scale-Out NFS (POSIX compliant, Distributed RW access to files), Amazon S3 compatible API with AI/ML S3X enhancements, iSCSI and NBD block interfaces, advanced global versioning with file-level granularity unlimited snapshots, global data deduplication and geo-transparent access to data from on-prem, private/public clouds or small footprint edge (IoT) devices.

<p align="center">
  <img src="https://github.com/Nexenta/edge-dev/raw/master/images/edgefs-multicloud.png?raw=true" alt="edgefs-multicloud.png"  width="75%" height="75%"/>
</p>

EdgeFS is capable of spanning unlimited number of geographically distributed sites (Geo-site), connected with each other as one global name space data fabric running on top of Kubernetes platform, providing persistent, fault-tolerant and high-performance fully compatible S3 Object API and [CSI volumes](https://github.com/Nexenta/edgefs-csi) for stateful Kubernetes Applications.

At each Geo-site, EdgeFS segment nodes deployed as containers (Kubernetes StatefulSet or Docker Compose) on physical or virtual nodes, pooling available storage capacity and presenting it via compatible S3/NFS/iSCSI/etc storage emulated protocols for cloud-native applications running on the same or dedicated servers.

## How it works, in a Nutshell?

If you familiar with "git", where all modifications are fully versioned and globally immutable, it is highly likely you already know how it works at its core. Think of it as a world-scale copy-on-write technique. Now, if we can make a parallel for you to understand it better - what EdgeFS does, it expands "git" paradigm to object storage and making Kubernetes Persistent Volumes accessible via emulated storage standard protocols e.g. S3, NFS and even block devices such as iSCSI, in a high-performance and low-latency ways. With fully versioned modifications, fully immutable metadata and data, users data can be transparently replicated, distributed and dynamically pre-fetched across many Geo-sites.

## Developer Guides, Services and APIs

* [Development Guide](https://github.com/Nexenta/edgefs/wiki/Development-Guide) - details on build environment
* [Harness Tests](https://github.com/Nexenta/edgefs/wiki/Harness-Tests) - details on how to run Harness Test package
* [Minimalistic CLI tool](https://github.com/Nexenta/edgefs/wiki/Minimalistic-CLI-tool) - CLI tool implemented in Go
* [LIBCCOW API](https://github.com/Nexenta/edgefs/wiki/LIBCCOW-library) - generic client library and its direct access API
* [NFS and FSIO API](https://github.com/Nexenta/edgefs/wiki/NFS-and-FSIO-library) - POSIX file system layer API
* [Block and LIBCCOWVOL API](https://github.com/Nexenta/edgefs/wiki/Block-and-LIBCCOWVOL-library) - Block device API and iSCSI/NBD integration
* [Edge-X S3 API](https://edgex.docs.apiary.io/) - details on advanced S3-compabile features, e.g. Versioned Edits, Snapshots, etc
* [FIO Engines](https://github.com/Nexenta/edgefs/wiki/FIO-Engines) - details on how to run FIO benchmarking tool at various directly conntected I/O layers
* [LIBPMU userspace networking](https://github.com/Nexenta/edgefs/wiki/LIBPMU-userspace-networking) - details on libpmu, DPDK-like library

## Build it (Production Image)

Make sure Docker package is installed on your build server with version >= 17.05 with support for staged builds.
Execute the following command:

<pre>
git clone git@github.com:Nexenta/edgefs.git
cd edgefs
docker build -t edgefs .
</pre>

## Quick Starts

Deployments:

* [Docker](https://github.com/Nexenta/edgefs/wiki/Quick-Start---Docker)
* [Kubernetes RookIO](https://github.com/Nexenta/edgefs/wiki/Quick-Start---Kubernetes-RookIO)

Configurations:

* [Initialization](https://github.com/Nexenta/edgefs/wiki/Quick-Start---Initialization) - generic initialization procedure, applicable 
* [Kubernetes RookIO Deployment](https://rook.io/docs/rook/master/edgefs-cluster-crd.html) - segment deployment procedure
* [Kubernetes RookIO CSI Integration](https://rook.io/docs/rook/master/edgefs-csi.html) - detailed instructions on how to get CSI configured with EdgeFS RookIO
* [Kubernetes RookIO Monitoring](https://rook.io/docs/rook/master/edgefs-monitoring.html) - Prometheus and Graphana integrations
* [Kubernetes RookIO VDEV Management](https://rook.io/docs/rook/master/edgefs-vdev-management.html) - disk/VDEV health checking, replacement, addition, etc
* [Kubernetes RookIO Upgrade](https://rook.io/docs/rook/master/edgefs-upgrade.html) - detailed instructions on how to execute rolling upgrade
* [Kubernetes RookIO GUI](https://rook.io/docs/rook/master/edgefs-ui.html) - segment dashboard, CRD wizard
* [Kubernetes RookIO NFS](https://rook.io/docs/rook/master/edgefs-nfs-crd.html) - setting up Scale-Out NFS (File)
* [Kubernetes RookIO S3](https://rook.io/docs/rook/master/edgefs-s3-crd.html) - setting up AWS S3 compatible interface (Object)
* [Kubernetes RookIO S3X AI/ML](https://rook.io/docs/rook/master/edgefs-s3x-crd.html) - setting up S3X interface for AI/ML, NoSQL and other intensive low latency workloads
* [Kubernetes RookIO iSCSI](https://rook.io/docs/rook/master/edgefs-iscsi-crd.html) - setting up Scale-Out iSCSI (Block)
* [Kubernetes RookIO ISGW (Global Namespaces)](https://rook.io/docs/rook/master/edgefs-isgw-crd.html) - setting up geo-transparent capable global name space
* [Kubernetes RookIO OpenStack/SWIFT)](https://rook.io/docs/rook/master/edgefs-swift-crd.html) - setting up OpenStack/SWIFT inteface (Object)

## Join our growing community!

* Users group: [edgefs-users](https://groups.google.com/forum/#!forum/edgefs)
* Slack channel: [slack channel](https://edgefs.slack.com)
* Twitter: [@edgefs_io](https://twitter.com/edgefsio)
* Telegram: [edgefs](https://t.me/edgefs)

### Community Meeting

A regular community meeting takes place monthly on every first [Tuesday at 10:00 AM PT (Pacific Time)](https://zoom.us/j/404796463).
Convert to your [local timezone](http://www.thetimezoneconverter.com/?t=10:00&tz=PT%20%28Pacific%20Time%29).

Any changes to the meeting schedule will be added to the [agenda doc](https://docs.google.com/document/d/1zU_xSN2I-d6EMJF3HSQlfceYuIlPFOJ3jWVYYoAqh8w/edit?usp=sharing) and posted to [Slack #users](https://edgefs.slack.com/messages/CDCUWDZP0) and the [edgefs-users mailing list](https://groups.google.com/forum/#!forum/edgefs).

Anyone who wants to discuss the direction of the project, design and implementation reviews, or general questions with the broader community is welcome and encouraged to join.
* Meeting link: https://zoom.us/j/404796463
* [Current agenda and past meeting notes](https://docs.google.com/document/d/1zU_xSN2I-d6EMJF3HSQlfceYuIlPFOJ3jWVYYoAqh8w/edit?usp=sharing)
* Past meeting recordings - coming
