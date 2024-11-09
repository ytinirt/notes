# TOC

<!-- TOC -->
* [TOC](#toc)
* [cgroup](#cgroup)
  * [cgroup子系统](#cgroup子系统)
    * [cpu和cpuacct cgroup](#cpu和cpuacct-cgroup)
      * [根据pod的cpu request和limit如何设置cpu cgroup参数](#根据pod的cpu-request和limit如何设置cpu-cgroup参数)
      * [cfs_period_us和cfs_quota_us进一步解释](#cfsperiodus和cfsquotaus进一步解释)
      * [分析命令](#分析命令)
    * [cpuset](#cpuset)
    * [memory](#memory)
    * [devices](#devices)
    * [pids](#pids)
  * [挂载cgroupfs](#挂载cgroupfs)
  * [判断是否为cgroupv2](#判断是否为cgroupv2)
  * [降级为cgroupv1](#降级为cgroupv1)
  * [常用操作](#常用操作)
    * [使用systemd管理cgroup](#使用systemd管理cgroup)
    * [查看统计信息](#查看统计信息)
* [namespaces](#namespaces)
  * [pid](#pid)
    * [找到host和容器内进程pid关系](#找到host和容器内进程pid关系)
    * [找到一个pidns下的进程](#找到一个pidns下的进程)
  * [mount](#mount)
    * [主机上查看和修改容器内文件](#主机上查看和修改容器内文件)
  * [常用命令](#常用命令)
  * [常用工具](#常用工具)
    * [lsns](#lsns)
    * [nsenter](#nsenter)
    * [unshare](#unshare)
* [OCI标准](#oci标准)
  * [运行时标准 runtime-spec](#运行时标准-runtime-spec)
  * [镜像标准 image-spec](#镜像标准-image-spec)
    * [manifest](#manifest)
    * [OCI Image Media Types](#oci-image-media-types)
    * [layer](#layer)
    * [blobs](#blobs)
  * [分发标准 distribution-spec](#分发标准-distribution-spec)
* [容器镜像](#容器镜像)
  * [从无到有制作基础镜像](#从无到有制作基础镜像)
  * [采用合并打包实现缩容](#采用合并打包实现缩容)
  * [移除基础镜像层实现缩容](#移除基础镜像层实现缩容)
  * [使用buildx构建多架构容器镜像](#使用buildx构建多架构容器镜像)
* [容器存储](#容器存储)
  * [overlay2](#overlay2)
    * [存储配额限制](#存储配额限制)
    * [容器可读可写层用量统计](#容器可读可写层用量统计)
    * [根据overlay数据目录digest反查容器/镜像](#根据overlay数据目录digest反查容器镜像)
  * [宿主机上直接修改容器内文件](#宿主机上直接修改容器内文件)
* [容器安全](#容器安全)
  * [Discretionary Access Control](#discretionary-access-control)
  * [linux capabilities](#linux-capabilities)
  * [seccomp](#seccomp)
    * [原理](#原理)
    * [确认操作系统和容器运行时支持seccomp](#确认操作系统和容器运行时支持seccomp)
    * [为pod设置seccomp自定义策略](#为pod设置seccomp自定义策略)
    * [排错](#排错)
      * [runc加载seccomp策略时报“OCI permission denied”](#runc加载seccomp策略时报oci-permission-denied)
  * [AppArmor](#apparmor)
    * [使用AppArmor的前置条件](#使用apparmor的前置条件)
  * [selinux](#selinux)
    * [深入学习](#深入学习)
    * [一次完整的报错分析](#一次完整的报错分析)
    * [常用操作](#常用操作-1)
    * [为Pod/容器设置selinux label](#为pod容器设置selinux-label)
    * [根据审计日志设置selinux规则](#根据审计日志设置selinux规则)
* [容器运行时](#容器运行时)
  * [runc](#runc)
    * [常用命令](#常用命令-1)
    * [cri-o如何通过conmon调用runc创建容器](#cri-o如何通过conmon调用runc创建容器)
  * [crun](#crun)
* [OCI](#oci)
  * [oci-hooks](#oci-hooks)
* [Containerd](#containerd)
  * [常用操作](#常用操作-2)
  * [如何编译containerd](#如何编译containerd)
  * [根据进程pid查询pod](#根据进程pid查询pod)
* [CRI-O](#cri-o)
  * [统计容器可读可写层存储用量](#统计容器可读可写层存储用量)
  * [指定seccomp profile](#指定seccomp-profile)
  * [容器存储目录](#容器存储目录)
  * [non-root用户使用devices](#non-root用户使用devices)
  * [检查容器存储数据量是否合理](#检查容器存储数据量是否合理)
  * [问题debug](#问题debug)
  * [Deep Dive](#deep-dive)
    * [创建容器](#创建容器)
    * [列出镜像ImageService/ListImages](#列出镜像imageservicelistimages)
* [podman](#podman)
  * [配置管理](#配置管理)
  * [使用podman查看cri创建的pod](#使用podman查看cri创建的pod)
  * [容器镜像和overlay/layer对应关系](#容器镜像和overlaylayer对应关系)
  * [在login后podman的认证信息可能存放的几个地方](#在login后podman的认证信息可能存放的几个地方)
  * [创建manifest list支持多架构镜像](#创建manifest-list支持多架构镜像)
  * [常用命令](#常用命令-2)
* [crictl](#crictl)
  * [直接创建容器](#直接创建容器)
    * [创建Pod Sandbox](#创建pod-sandbox)
    * [创建业务容器](#创建业务容器)
    * [如何配置](#如何配置)
  * [查看容器资源用量](#查看容器资源用量)
    * [容器可读可写层存储占用top10](#容器可读可写层存储占用top10)
    * [容器可读可写层inode占用top10](#容器可读可写层inode占用top10)
* [Docker](#docker)
  * [容器环境下的swap使用](#容器环境下的swap使用)
  * [深入docker stats命令](#深入docker-stats命令)
  * [Docker问题定位](#docker问题定位)
    * [Docker卡死hang住](#docker卡死hang住)
  * [Docker操作](#docker操作)
    * [常用操作](#常用操作-3)
    * [提取镜像rootfs文件](#提取镜像rootfs文件)
    * [docker build构建镜像](#docker-build构建镜像)
    * [安装指定版本docker](#安装指定版本docker)
    * [关闭docker0](#关闭docker0)
    * [修改容器的ulimit默认配置](#修改容器的ulimit默认配置)
    * [使用docker-storage-setup初始化docker存储](#使用docker-storage-setup初始化docker存储)
    * [构建Docker镜像最佳实践（Alpine）](#构建docker镜像最佳实践alpine)
    * [强制删除容器](#强制删除容器)
    * [找到容器使用的dm-xx设备](#找到容器使用的dm-xx设备)
    * [docker pull加速](#docker-pull加速)
    * [docker使用代理](#docker使用代理)
    * [容器文件系统使用率统计](#容器文件系统使用率统计)
    * [强制重启Docker服务](#强制重启docker服务)
* [镜像仓库和工具](#镜像仓库和工具)
  * [skopeo](#skopeo)
    * [镜像搬运工](#镜像搬运工)
    * [Windows环境上源码运行skopeo搬运镜像](#windows环境上源码运行skopeo搬运镜像)
<!-- TOC -->

# cgroup

cgroup的原生接口通过cgroupfs提供，类似于procfs和sysfs，是一种虚拟文件系统，用户可以通过文件操作实现cgroup的组织管理。

cgroup可以限制、记录、隔离进程组所使用的物理资源。

子进程创建之初，与其父进程处于同一个cgroup的控制组里。

cgroup实现本质上是给系统进程挂上hooks，当task运行过程中涉及到某类资源的使用时就会触发hook上附带的子系统进行检测。

主要作用包括：

- 资源限制：可以对进程组使用的资源总额进行限制（例如内存上限，一旦超过配额就触发OOM异常）
- 优先级分配：通过分配的CPU时间片数量及硬盘IO带宽大小，相当于控制进程运行的优先级
- 资源统计：统计系统的资源使用量，如CPU使用时长、内存用量等，非常适用于计费和监控
- 进程控制：对进程组执行挂起、恢复等操作

## cgroup子系统

| 类型         | 说明                                                                            |
|------------|-------------------------------------------------------------------------------|
| cpuset     | 为cgroup中的task分配独立的cpu（针对多处理器系统）和内存                                            |
| cpu        | 控制task对cpu的使用                                                                 |
| cpuacct    | 自动生成cgroup中task对cpu资源使用情况的报告                                                  |
| memory     | 设定cgroup中task对内存使用量的限定，并且自动生成这些task对内存资源使用情况的报告                               |
| blkio      | 为块设备设定输入/输出限制                                                                 |
| devices    | 开启或关闭cgroup中task对设备的访问                                                        |
| freezer    | 挂起或恢复cgroup中的task                                                             |
| net_cls    | docker没有直接使用，其通过使用等级识别符（classid）标记网络数据包，从而允许Linux流量控制（TC）程序识别从具体cgroup中生成的数据包 |
| perf_event | 对cgroup中的task进行统一的性能测试                                                        |
| hugetlb    | TODO                                                                          |

### cpu和cpuacct cgroup
| 配置                   | 说明                                                                                                                                                                             |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| cpu.cfs_burst_us     | CFS调度器，允许在一个period内，cpu资源用量超过quota限制，预支的部分在后面的period里扣减出去。                                                                                                                     |
| cpu.cfs_period_us    | cfs周期，单位微秒，默认值100000                                                                                                                                                           |
| cpu.cfs_quota_us     | 用以配置在当前cfs周期下能够获取的调度配额，单位微秒，如果给95%个核则配置95000，如果给5个核则配置500000，默认值-1表示不受限                                                                                                        |
| cpu.shares           | 各cgroup共享cpu的权重值，默认1024，闲时cpu用量能超过根据权重计算的共享比例，忙时根据共享比例分配cpu资源                                                                                                                  |
| cpu.stat             | **nr_periods**, 表示过去了多少个cpu.cfs_period_us里面配置的时间周期<br>**nr_throttled**, 在上面的这些周期中，有多少次是受到了限制（即cgroup中的进程在指定的时间周期中用光了它的配额）<br>**throttled_time**, cgroup中的进程被限制使用CPU持续了多长时间(纳秒) |
| cpu.idle             |                                                                                                                                                                                |
| cpuacct.usage        | 所有cpu核的累加使用时间(nanoseconds)                                                                                                                                                     |
| cpuacct.usage_percpu | 针对多核，输出的是每个CPU的使用时间(nanoseconds)                                                                                                                                               |
| cpuacct.stat         | 输出系统（system/kernel mode）耗时和用户（user mode）耗时，单位为USER_HZ。                                                                                                                         |

`cpu.shares`用于设置下限，在cpu繁忙时生效。`cpu.cfs_period_us`和`cpu.cfs_quota_us`设置硬上限。

参见：
- [限制cgroup的CPU使用（subsystem之cpu）](https://segmentfault.com/a/1190000008323952)
- [CFS Bandwidth Control](https://www.kernel.org/doc/Documentation/scheduler/sched-bwc.txt)
- [Linux cgroup资源隔离各个击破之 - cpu隔离1](https://developer.aliyun.com/article/54483)
- [CFS Scheduler](https://www.kernel.org/doc/Documentation/scheduler/sched-design-CFS.txt)

#### 根据pod的cpu request和limit如何设置cpu cgroup参数
建一个测试Pod，其`resources`配置如下：
```bash
    resources:
      requests:
        cpu: 0
      limits:
        cpu: 1
```

创建Pod后可确认：
* **调度效果**：对request没有要求，不会占节点的allocated request数。
* **QoS类型**：Burstable

进一步查看cpu cgroup参数：
```bash
# cat cpu.cfs_period_us
100000
# cat cpu.cfs_quota_us
100000
# cat cpu.shares
2
```
* 可看到 _cpu.cfs_quota_us_ / _cpu.cfs_period_us_ 为1，这个是上限。
* *cpu.shares*为2，而一个核的权重为1024，因此2/1024近乎为0，可看到下限配置很低，对应`request 0`。


作为对比，更新测试Pod的`resources`配置如下：
```bash
    resources:
      requests:
        cpu: 0.5
      limits:
        cpu: 1.5
```
这时cpu cgroup参数如下：
```bash
# cat cpu.cfs_period_us
100000
# cat cpu.cfs_quota_us
150000
# cat cpu.shares
512
```
* 可看到 _cpu.cfs_quota_us_ / _cpu.cfs_period_us_ 为1.5，这个是上限。
* *cpu.shares* / 1024 为0.5，对应`request 0.5`。

#### cfs_period_us和cfs_quota_us进一步解释
period为100000、quota为50000和period为10000、quota为5000，容器的cpu limit均为0.5核，有什么区别？
* 每个period内，最多执行quota时间。如果在quota时间内未执行完，将被throttle（统计到stat里），并只能等待下一个period继续执行。
* period越大，整体吞吐能力越好、削峰效果越好，但会导致实时性变差，反之亦然。

辅以cfs_burst_us，能既获取良好的吞吐能力，又兼顾实时性，具体的：
* CFS调度器，允许在一个period内，cpu资源用量超过quota限制，预支的部分在后面的period里扣减出去。

#### 分析命令
```bash
# CPU周期次数
old=0
new=0
while true; do
    new=$(cat cpu.stat | grep nr_periods | awk '{print $2}')
    delta=$((new-old))
    echo "$(date) $delta"
    old=$new
    sleep 1s
done

# CPU限速次数
old=0
new=0
while true; do
    new=$(cat cpu.stat | grep nr_throttled | awk '{print $2}')
    delta=$((new-old))
    echo "$(date) $delta"
    old=$new
    sleep 1s
done

# 单个容器徒手实现 crictl stats --seconds 10 得效果
cid=xxx
while true; do
    start=$(crictl stats -o json $cid | jq -r '.stats[0].cpu | .timestamp + " " + .usageCoreNanoSeconds.value')
    sleep 10s
    finished=$(crictl stats -o json $cid | jq -r '.stats[0].cpu | .timestamp + " " + .usageCoreNanoSeconds.value')

    ts_start=$(echo $start | cut -d' ' -f1)
    usage_start=$(echo $start | cut -d' ' -f2)
    ts_finished=$(echo $finished | cut -d' ' -f1)
    usage_finished=$(echo $finished | cut -d' ' -f2)

    ts_delta=$((ts_finished - ts_start))
    usage_delta=$((usage_finished - usage_start))
    usage=$(echo $(awk -v usage_delta="$usage_delta" -v ts_delta="$ts_delta" 'BEGIN {print usage_delta * 100 / ts_delta}') | cut -d. -f1)

    echo "$(date) $usage%"
done
```

### cpuset
遍历所有kubernetes pod的cpu亲和性：
```bash
for f in $(find /sys/fs/cgroup/cpuset -name "cpuset.cpus"); do printf "%-220s %s\n" $f $(cat $f); done
```

### memory
TODO: cgroup v1的oom，文件缓存*file_dirty* 和 *file_writeback* 的内存用量，这部分也记到容器内存，可能导致oom。
参见链接[cgroup-v2](https://docs.kernel.org/admin-guide/cgroup-v2.html) 。

其它相关说明：
* 系统参数`vm.dirty*`，参见[更加积极的脏页缓存刷新](./os.md#更加积极的脏页缓存刷新) 。针对大内存节点，调优 vm.dirty 参数，更加积极的脏数据刷新，避免脏页积累导致的容器内 file_dirty 和 file_writeback 过大、容器OOM。
* 读写文件时*Direct I/O*参数，即`O_DIRECT`标识，避免文件系统缓存，不过相应的带来IO性能降低。
* cgroupv2会限制内存group中pagecache内存用量，因此能避免上述oom。

### devices
```bash
echo "b 7:0 rwm" > /sys/fs/cgroup/devices/kubepods.slice/devices.allow
```

### pids
可用于控制容器的进程数：
```
pids.current  pids.events   pids.max
```

检查pids数TOP20：
```bash
for p in $(find /sys/fs/cgroup/pids/ -name "pids.current"); do echo "$(cat $p) $p"; done | sort -rn | head -n20
```

## 挂载cgroupfs

以cpuset子系统为例：

```bash
mount -t cgroup -o cpuset cpuset /sys/fs/cgroup/cpuset
```

## 判断是否为cgroupv2
```bash
mkdir /tmp/hehe
# 看能否挂载成功
mount -t cgroup2 none /tmp/hehe

# 另一种方法，看能否搜索到 cgroup2
grep cgroup /proc/filesystems
```

## 降级为cgroupv1
主机上修改grub配置，重启主机生效：
```bash
sudo grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=0"
```

## 常用操作

### 使用systemd管理cgroup
```bash
systemd-cgls   # 查看systemd cgroup的配置层级关系
systemd-cgtop  # 基于cgroup，直接查看cpu和内存的使用情况
```

```bash
mount -t cgroup
lssubsys -m
ls -l /sys/fs/cgroup/
lscgroup
man cgconfig.conf
cgcreate
cgdelete
```


### 查看统计信息
```bash
# 全量统计信息
cat /proc/cgroups

```


# namespaces

进一步阅读:
* [The 7 most used Linux namespaces](https://www.redhat.com/sysadmin/7-linux-namespaces)
* [Building a Linux container by hand using namespaces](https://www.redhat.com/sysadmin/building-container-namespaces)

## pid

### 找到host和容器内进程pid关系
host上，查看进程的status文件，可看到其在容器内的pid：
```bash
# cat /proc/<pid>/status | grep NSpid
NSpid:  12345   2
```
其中第1列是进程在host上的pid，第2列是容器内的pid。

进一步阅读:
* [Building containers by hand: The PID namespace](https://www.redhat.com/sysadmin/pid-namespace)

### 找到一个pidns下的进程
```bash
# 找到一个process的pid命名空间(inode)，适用于容器内或者host上执行
ls -Li /proc/<pid>/ns/pid
# 也可以列出全部的pid命名空间
lsns -t pid

# host上遍历寻找所有该pid命名空间下的进程，其中xxxxxxxxxx是pidns的inode
ps -eo pidns,pid,lwp,cmd | awk '$1==xxxxxxxxxx'
```

## mount
进一步阅读:
* [Building a container by hand using namespaces: The mount namespace](https://www.redhat.com/sysadmin/mount-namespaces)

### 主机上查看和修改容器内文件
```bash
nsenter -t $(pidof xxx) -m ls
nsenter -t $(pidof xxx) -m vi /path/to/file
```

## 常用命令
```bash
# 查看ns的inode信息
ls -Li /proc/1/ns/net
# TODO: https://unix.stackexchange.com/questions/113530/how-to-find-out-namespace-of-a-particular-process

# 查看pid所述的容器/pod
nsenter -t ${pid} -u hostname

# 查看pid所在容器的内存用量
nsenter -t ${pid} -m cat /sys/fs/cgroup/memory/memory.usage_in_bytes

# 查看pid所在容器的cpu使用率（近10秒）
function cpu-usage {
  local pid=$1
  local start=$(nsenter -t ${pid} -m cat /sys/fs/cgroup/cpu/cpuacct.usage 2>/dev/null)
  sleep 10s
  local end=$(nsenter -t ${pid} -m cat /sys/fs/cgroup/cpu/cpuacct.usage 2>/dev/null)
  if [ "${start}" != "" ] && [ "${end}" != "" ]; then
    # echo "(${end} - ${start}) / 100000000" | bc
    local cpuacct=$[${end} - ${start}]
    echo $[${cpuacct}/100000000]%
  fi
}
```

## 常用工具

### lsns

`lsns`工具来自包`util-linux`，其常见使用如下：

```bash
# 查看网络命名空间列表
lsns -t net

# 查看pid命名空间列表
lsns -t pid
```



### nsenter

```bash
nsenter --net=/proc/19714/ns/net ip addr
nsenter -t 19714 -u hostname
nsenter -t 19714 -m -u -i -n -p bash
nsenter -t 19714 -m -p bash
nsenter -t 12472 -m -p umount /var/lib/origin/openshift.local.volumes/pods/<uid>/volumes/ctriple.cn~drbd/r0002
nsenter -t 19714 -m -p ps -ef
nsenter -t ${pid} -m cat /sys/devices/virtual/net/eth0/iflink 2>/dev/null
nsenter -t 7429 -n cat /proc/net/route
nsenter -t 12345 -n tcpdump -i eth0 -nnl  # 关联容器的网络命名空间，直接在宿主机上抓容器里eth0接口的报文
nsenter -t 14756 -n ip link set eth0 address ee:ee:ee:ee:ee:ee # 修改容器 MAC 地址
```



### unshare

使用不同的命名空间运行程序，详见`man 1 unshare`

>run program with some namespaces unshared from parent


# OCI标准
## 运行时标准 runtime-spec

## 镜像标准 image-spec
标准链接[image-spec](https://github.com/opencontainers/image-spec/blob/main/spec.md)

### manifest
包括如下信息：
* **layer**, that will be unpacked to make up the final runnable filesystem.
* **image config**, includes information such as application arguments, environments, etc.
* **image index**, a higher-level manifest which points to a list of manifests and descriptors.

最终能够`unpacked into an OCI Runtime Bundle.`

### OCI Image Media Types
https://github.com/opencontainers/image-spec/blob/main/media-types.md

### layer


### blobs
```bash
$ shasum -a 256 ./blobs/sha256/afff3924849e458c5ef237db5f89539274d5e609db5db935ed3959c90f1f2d51
afff3924849e458c5ef237db5f89539274d5e609db5db935ed3959c90f1f2d51 ./blobs/sha256/afff3924849e458c5ef237db5f89539274d5e609db5db935ed3959c90f1f2d51
```

## 分发标准 distribution-spec

# 容器镜像
## 从无到有制作基础镜像
比如制作一个CentOS操作系统的基础镜像，使用CentOS的yum源即可：
```bash
mkdir -p /tmp/test/baseimage
# 往/tmp/test/baseimage这个目录安装bash和yum，过程中会自动解决依赖
yum -c /etc/yum.conf --installroot=/tmp/test/baseimage --releasever=/  install bash yum

# 进入目录可以看到rootfs
[root@xxx baseimage]# ls
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
# 此时，可以手动修改rootfs中的文件，例如修改etc/yum.repos.d目录下*.repo，定制仓库路径

# 生成并上传基础镜像
tar --numeric-owner -c -C "/tmp/test/baseimage" . | docker import - docker.io/ytinirt/baseimage:v1
docker push docker.io/ytinirt/baseimage:v1
```

## 采用合并打包实现缩容
TODO

## 移除基础镜像层实现缩容
在无法合并打包时，可采用移除基础镜像层的方式实现应用镜像的缩容。

大致原理为，确保目的地容器存储中已存在基础镜像，可将应用镜像中包含于基础镜像的layer删除并重新打包应用镜像，实现应用镜像缩容的目的。
传输到目的地，加载镜像时，虽然应用镜像tar包中没有基础镜像layer，但目的地容器存储中已存在对应的基础layer，因此应用镜像也能加载成功。

## 使用buildx构建多架构容器镜像
参考资料：
- https://docs.docker.com/buildx/working-with-buildx/
- https://medium.com/@artur.klauser/building-multi-architecture-docker-images-with-buildx-27d80f7e2408
- https://github.com/docker/buildx
- https://github.com/docker/buildx/issues/80

环境要求：
- 内核版本：4.8及以上（如果用CentOS，建议直接装CentOS 8）
- Docker版本： 19.03及以上（要使用buildx，19.x版本可能需要开启docker Experimental mode。而20.10.8已默认开启buildx命令。建议使用最新版本的Docker）

环境准备和Demo
```bash
# 通过容器方式，准备多架构编译环境（注意，节点重启后需要重新run一次容器）
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

# 创建并使用builder
docker buildx create --use --name mybuilder --driver-opt network=host
# 此处使用主机网络"network=host"，能用到宿主机/etc/hosts，是为了解决私有仓库域名解析的问题

# 检查builder，并触发其准备就绪，实际上就是启一个buidler容器
docker buildx inspect --bootstrap

# 拷贝为私有仓库签发证书的CA的证书到builder容器，并重启builder容器，解决私有仓库证书问题
BUILDER_ID=$(docker ps|grep 'moby/buildkit' | awk '{print $1}')
docker cp </path/to/ca.crt> ${BUILDER_ID}:/etc/ssl/certs/ca-certificates.crt
docker restart ${BUILDER_ID}

# 查看builder，已支持多种架构
docker buildx ls
# 类似如下输出，可看到支持多种架构
# NAME/NODE    DRIVER/ENDPOINT             STATUS  PLATFORMS
# mybuilder *  docker-container
#   mybuilder0 unix:///var/run/docker.sock running linux/amd64, linux/arm64, linux/riscv64, linux/ppc64le, linux/s390x, linux/386, linux/mips64le, linux/mips64, linux/arm/v7, linux/arm/v6

# 准备镜像的Dockerfile和依赖资源文件，例如
cat << EOF > Dockerfile
FROM alpine:latest
CMD echo "Running on $(uname -m)"
EOF

# 登录镜像仓库

# 构建多架构镜像，并自动以manifest list方式push到镜像仓库
docker buildx build -t "ytinirt/buildx-test:latest" --platform linux/amd64,linux/arm64 --push .

# 查看镜像
docker manifest inspect ytinirt/buildx-test:latest

# 可选：删除builder，什么都没发生过
docker buildx rm mybuilder
```


# 容器存储

## overlay2

### 存储配额限制
参见[storage-driver-options](https://docs.docker.com/engine/reference/commandline/dockerd/#storage-driver-options)。即使采用overlay2存储驱动，也可以借助xfs的pquota特性，为容器rw层做限制。
> overlay2.size
>
> Sets the default max size of the container. It is supported only when the backing fs is xfs and mounted with pquota mount option. Under these conditions the user can pass any size less than the backing fs size.

更进一步，通过`xfs`文件系统的`pquota`属性，可以实现文件夹级别的存储配额限制。

### 容器可读可写层用量统计
```bash
# 进入overlay的数据目录
cd /var/lib/containers/storage/overlay
# 统计容器可读可写层新增文件大小统计排序
for d in $(find . -name "diff"  -type d -maxdepth 2 2>/dev/null); do du -sh $d 2>/dev/null; done | grep -v ^0  | grep -v K | sort -n
```

### 根据overlay数据目录digest反查容器/镜像
```bash
for cid in $(crictl ps -a -q ); do echo $cid; crictl inspect $cid | grep </var/lib/containers/storage/overlay文件夹下的目录>; done
for cid in $(podman ps -aq); do echo $cid; podman inspect $cid | grep </var/lib/containers/storage/overlay文件夹下的目录>; done
for iid in $(crictl img | sed 1d | awk '{print $3}'); do echo $iid; crictl inspecti $iid | grep </var/lib/containers/storage/overlay文件夹下的目录>; done

```

## 宿主机上直接修改容器内文件

宿主机上`/proc/{pid}/cwd`是pid所在进程当前的工作路径，如果pid是容器中业务进程在宿主机上的进程号，那么cwd文件夹中能直接看到容器中“当前工作目录”。
因此，宿主机上直接修改cwd文件夹中的内容，也能在容器中生效。


# 容器安全

参考文档：

- [Overview Of Linux Kernel Security Features](https://www.linux.com/tutorials/overview-linux-kernel-security-features/)
- [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Pod Security Policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)

## Discretionary Access Control

通过user ID (UID)和group ID (GID)，实行访问控制。

为Pod/容器的安全上下文securityContext设置uid和gid：

~~~yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
  volumes:
  - name: sec-ctx-vol
    emptyDir: {}
  containers:
  - name: sec-ctx-demo
    image: busybox
    command: [ "sh", "-c", "sleep 1h" ]
    volumeMounts:
    - name: sec-ctx-vol
      mountPath: /data/demo
    securityContext:
      runAsUser: 2000
      allowPrivilegeEscalation: false
~~~

其中fsGroup施加到volume上，修改volume下文件/文件夹的GID。



## linux capabilities

定义文档参见[capability.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h)

查看当前进程的capabilities

~~~bash
# cat /proc/$$/status | grep Cap
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
~~~

为Pod设置capabilities

~~~yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  containers:
  - name: sec-ctx
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      capabilities:
        add: ["SYS_TIME", "SYS_ADMIN"]
~~~
* 增加`SYS_ADMIN`，容器内能够`mount`操作。
* 增加`SYS_TIME`，容器内能够设置系统时间。


注意，在add和drop时，去掉了前缀`CAP_`。

进一步[阅读](https://cloud.redhat.com/blog/linux-capabilities-in-openshift) 。

## seccomp

### 原理
参考资料[seccomp](https://docs.docker.com/engine/security/seccomp)

SECure COMPuting mode (简称seccomp)是Linux内核一种特性（Linux kernel feature）。能够过滤系统调用（Filter a process’s system calls）。
相较linux capabilities，权限控制粒度更细。
利用seccomp特性，Docker能够限制容器中能够访问的系统调用（system call），防止容器中的操作危害整个节点。


### 确认操作系统和容器运行时支持seccomp
通过如下操作，确认Linux和Docker支持seccomp：
```bash
[root@zy-super-load docker]# docker info
...
Security Options:
 seccomp
  WARNING: You're not using the default seccomp profile
  Profile: /etc/docker/seccomp.json
 selinux
Kernel Version: 3.10.0-862.14.4.el7.x86_64
...
[root@zy-super-load docker]# grep 'CONFIG_SECCOMP=' /boot/config-$(uname -r)
CONFIG_SECCOMP=y
```

从上述docker info中看到，docker的seccomp配置文件路径为`/etc/docker/seccomp.json`。
该配置文件采用白名单模式，即容器内可访问seccomp.json列出的系统调用，除此之外的系统调用无法访问，默认（SCMP_ACT_ERRNO）返回Permission Denied。

### 为pod设置seccomp自定义策略
以设置系统时间为例：
~~~bash
[root@zy-super-load ~]# strace date -s "15:22:00" 2>&1| grep -i time
...
clock_settime(CLOCK_REALTIME, {1575530520, 0}) = 0
...
~~~

其用到了系统调用`clock_settime`。
为Pod设置seccomp profile
```yaml
apiVersion: v1
kind: ReplicationController
...
spec:
  replicas: 1
  selector:
    app: seccomp-demo
  template:
    metadata:
      annotations:
        seccomp.security.alpha.kubernetes.io/pod: "localhost/test-profile.json"
      labels:
        app: seccomp-demo
    spec:
      containers:
      - command:
        - /bin/bash
...
```
当指定为`localhost`时，默认从`/var/lib/kubelet/seccomp/`中搜索profile文件，详见`kubelet`的`--seccomp-profile-root`参数。
当`test-profile.json`中禁止系统调用`clock_settime`后，在pod中使用date设置系统时间失败。

### 排错

#### runc加载seccomp策略时报“OCI permission denied”
详见[issue](https://github.com/containers/common/issues/631)

## AppArmor
https://kubernetes.io/docs/tutorials/security/apparmor/

AppArmor通过调整配置文件（Profile）进行策略配置，以允许特定程序或容器所需的访问， 如 Linux 权能字、网络访问、文件权限等。
每个Profile都可以在 强制（enforcing） 模式（阻止访问不允许的资源）或 投诉（complain） 模式（仅报告冲突）下运行。

AppArmor的Profile施加到Pod的每个容器上，具体的，通过Pod的注解指定容器及其使用的Profile，注解示例如下：
```
container.apparmor.security.beta.kubernetes.io/<container_name>: <profile_ref>
```

### 使用AppArmor的前置条件
1. 检查是否开启AppArmor内核模块
    ```bash
    # 输出为Y
    cat /sys/module/apparmor/parameters/enabled
    # 或者
    cat /boot/config-$(uname -r) | grep CONFIG_SECURITY_APPARMOR
    ```
2. 容器运行时支持AppArmor，主流的容器运行时，例如containerd和cri-o，均支持AppArmor
3. AppArmor的Profile文件已加载，如果Profile文件未加载，kubelet将拒绝创建使用该Profile的Pod
    ```bash
    # 查看已加载的Profile文件
    cat /sys/kernel/security/apparmor/profiles | sort
    ```

## selinux

参考资料[HowTos/SELinux](https://wiki.centos.org/HowTos/SELinux)

SELinux是对文件（file）和资源（例如process、device等）的访问权限控制，是对传统的discretionary access control (DAC) 的补充。
SELinux参照最小权限模型（the model of least-privilege）设计，与之匹配的是严格策略（the strict policy），除非显式配置指定否则默认情况下所有访问均被拒绝（denied）。
但strict policy过于严格、不便使用，为此CentOS定义并默认采用基于目标的策略（the targeted policy），只针对选取的系统进程进行限制，这些进程（例如 httpd, named, dhcpd, mysqld）涉及敏感信息和操作。其它系统进程和用户进程则处于未限制域（unconfined domain）中，不由SELinux控制和保护。

targeted policy有四种形式的访问控制：

| 类型                               | 描述                                                                                                                                                   |
|----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| Type Enforcement (TE)            | Type Enforcement is the primary mechanism of access control used in the targeted policy                                                              |
| Role-Based Access Control (RBAC) | Based around SELinux users (not necessarily the same as the Linux user), but not used in the default configuration of the targeted policy            |
| Multi-Level Security (MLS)       | Not commonly used and often hidden in the default targeted policy                                                                                    |
| Multi-Category Security(MCS)     | An extension of Multi-Level Security, used in the targeted policy to implement compartmentalization of virtual machines and containers through sVirt |

所有进程和文件都含有SELinux安全啥下文（SELinux security context）信息
```bash
[root@op-master containers]# pwd
/var/lib/docker/containers
[root@op-master containers]# docker ps | grep nginx
...
6b312ef59368 nginx:1.14-alpine "nginx -g 'daemon ..."   4 days ago          Up 4 days           80/tcp, 0.0.0.0:8888->8888/tcp   apiserver-proxy
[root@op-master containers]# cd 6b312ef59368/
[root@op-master 6b312ef59368]# ls -Z config.v2.json
-rw-r--r--. root root system_u:object_r:container_var_lib_t:s0 config.v2.json
[root@op-master 6b312ef59368]#
```
其中，`system_u:object_r:container_var_lib_t:s0`就是在标准的DAC上增加的SELinux安全上下文信息。格式为`user:role:type:mls`，因此类型为`container_var_lib_t`。

```bash
[root@op-master ~]# ps -efZ | grep 6b312ef593
system_u:system_r:container_runtime_t:s0 root 22190 18571  0 Apr12 ?   00:00:38 /usr/bin/docker-containerd-shim-current 6b312ef59368 /var/run/docker/libcontainerd/6b312ef59368 /usr/libexec/docker/docker-runc-current
```
可看到该容器的shim进程SELinux安全上下文，标识该进程类型为`container_runtime_t`，与上述config.v2.json文件的类型`container_var_lib_t`类似、均属于container_t域下，因此shim进程可以访问该文件。


### 深入学习
TODO:
* https://blog.csdn.net/xsm666/article/details/81357363
* https://danwalsh.livejournal.com/81756.html


### 一次完整的报错分析
```
Apr 01 09:43:22 master0 setroubleshoot[1417162]: SELinux is preventing /usr/sbin/xtables-nft-multi from ioctl access on the directory /sys/fs/cgroup. For complete SELinux messages run: sealert -l e1a4eb18-019a-4552-bd0c-4706ada83ab9
Apr 01 09:43:22 master0 setroubleshoot[1417162]: SELinux is preventing /usr/sbin/xtables-nft-multi from ioctl access on the directory /sys/fs/cgroup.

                                                 *****  Plugin catchall (100. confidence) suggests   **************************

                                                 If you believe that xtables-nft-multi should be allowed ioctl access on the cgroup directory by default.
                                                 Then you should report this as a bug.
                                                 You can generate a local policy module to allow this access.
                                                 Do
                                                 allow this access for now by executing:
                                                 # ausearch -c 'iptables' --raw | audit2allow -M my-iptables
                                                 # semodule -X 300 -i my-iptables.pp

Apr 01 09:43:22 master0 setroubleshoot[1417162]: AnalyzeThread.run(): Set alarm timeout to 10
```

### 常用操作
```bash
# 设置SELinux模式
setenforce 0

# 查询当前SELinux模式
getenforce

# 查看SELinux状态
sestatus

# 设置具体elements的SELinux策略
semanage

# 查看文件的SELinux标签
ls -Z

# 查看进程的SELinux标签
ps -efZ

# 设置文件的SELinux标签
chcon
chcon -v --type=httpd_sys_content_t /html
chcon -Rv --type=httpd_sys_content_t /html
chcon -R --type container_file_t /var/lib/hostdir

restorecon -R /html

# 查看审计日志
ausearch -m avc --start recent
ausearch -ui 0
setsebool -P virt_use_nfs 1
```


### 为Pod/容器设置selinux label
```yaml
...
securityContext:
  seLinuxOptions:
    level: "s0:c123,c456"
...
```
其中seLinuxOptions施加到volume上。一般情况下，只需设置level，其为Pod及其volumes设置Multi-Category Security (MCS) label。
注意，一旦为Pod设置了MCS label，其它所有相同label的pod均可访问该Pod的volume。

### 根据审计日志设置selinux规则
若遇到selinux拦截操作，例如:
```
SELinux is preventing /usr/sbin/lldpad from sendto access on the unix_dgram_socket ...
```

可以使用如下命令放开拦截：
```bash
ausearch -m avc --start recent

# 根据审计日志，查找被拦截的操作，并生成允许的规则
ausearch -c 'lldpad' --raw | audit2allow -M my-lldpad
# 设置selinux，放开拦截
semodule -X 300 -i my-lldpad.pp
```

# 容器运行时
## runc
### 常用命令
```bash
# 查看容器列表
runc --root=/run/containerd/runc/k8s.io list

# 查看容器进程信息
# 其中<cid>可以通过 ctr -n k8s.io c ls | grep <image-name> 获取
runc --root /run/containerd/runc/k8s.io ps <cid>

# 进入容器执行命令
runc --root /run/containerd/runc/k8s.io exec -t <cid> bash

# 使用resume命令，解除paused状态
runc --root=/run/containerd/runc/k8s.io resume <cid>

# 更新容器资源配置
runc update --cpu-share 100 <cid>
```

### cri-o如何通过conmon调用runc创建容器
```
# 命令示例
/usr/bin/runc
    --systemd-cgroup
    --root=/run/runc
    create
    --bundle /run/containers/storage/overlay-containers/<cid>/userdata
    --pid-file /run/containers/storage/overlay-containers/<cid>/userdata/pidfile
    <cid>
```

## crun
C语言实现的容器运行时。

资料：
* [introduction](https://www.redhat.com/sysadmin/introduction-crun)
* [fedora-31-control-group-v2](https://www.redhat.com/sysadmin/fedora-31-control-group-v2)

# OCI
## oci-hooks
配置一个hook：
```bash
# cat /etc/containers/oci/hooks.d/hook.json
{
  "version": "1.0.0",
  "hook": {
    "path": "/root/runtime-hook.sh",
    "args": ["runtime-hook.sh"]
  },
  "when": {
    "annotations": {
      "^ANNON\\.HEHE$": ".*"
    }
  },
  "stages": ["prestart"]
}
```

hook执行操作：
```bash
# cat /root/runtime-hook.sh
#!/bin/bash

echo "$@" >> /root/runtime-hook.log
env >> /root/runtime-hook.log
echo >> /root/runtime-hook.log
```

# Containerd
## 常用操作
```bash
# 在线收集containerd的dump信息，堆栈文件保存在/tmp目录中
kill -s SIGUSR1 $(pidof containerd)

# 批量导出容器
ctr -n k8s.io i export image.tar coredns:v1.7.0 kube-proxy:v1.18.8

# 使用containerd客户端
docker-ctr-current --address unix:///var/run/docker/libcontainerd/docker-containerd.sock

# 日志查看
# 方式1： 目录 /var/run/containerd/io.containerd.grpc.v1.cri/containers 下能够看到容器stdout和stderr的pipe文件。
# 直接cat pipe文件，就能看到标准和错误输出。注意，这里只能看到实时输出。
cat /var/run/containerd/io.containerd.grpc.v1.cri/containers/<容器id>/io/2615573161/<容器id>-stdout
# 方式2： 目录 /var/log/pods 下能够看到kubelet保存的容器日志输出，kubelet也是使用上了上述1把容器的stdout和stderr输出到/var/log下，
# 实现查看历史日志得能力，提升易用性。
cat /var/log/pods/kube-system_apiserver-proxy-xxx/nginx/0.log

# 查看容器指标信息，例如cpu、内存开销
ctr -n k8s.io t metric <cid>

# 挂载镜像
ctr -n k8s.io i mount centos:8 /mnt
# 解除挂载
ctr -n k8s.io i unmount /mnt
```

## 如何编译containerd
可直接在ARM架构的环境编译aarch64，如下示例包含containerd与runc
```bash
docker run -it --privileged --network host\
    -v /var/lib/containerd \
    -v ${PWD}/runc:/go/src/github.com/opencontainers/runc \
    -v ${PWD}/containerd:/go/src/github.com/containerd/containerd \
    -e GOPATH=/go \
    -w /go/src/github.com/containerd/containerd containerd/build-aarch64:1.1.0 sh
# 进入容器里操作
# 编译 runc
cd /go/src/github.com/opencontainers/runc
make
# 编译 containerd
cd /go/src/github.com/containerd/containerd
make
```

## 根据进程pid查询pod
```bash
function pid2pod {
  local pid=$1
  if [ -f /proc/${pid}/cgroup ]; then
    local cid=$(cat /proc/${pid}/cgroup | grep ":memory:" | awk -F '/' '{print $NF}' | awk -F ':' '{print $NF}' | sed 's/^cri-containerd-//g' | sed 's/.scope$//g' | grep -v "^crio-")
    if [ "${cid}" = "" ]; then
      # Try cri-o
      cid=$(cat /proc/${pid}/cgroup | grep -m1 "/crio-" | awk -F '/' '{print $NF}' | sed 's/^crio-//g' | sed 's/^conmon-//g' | sed 's/.scope$//g')
      if [ "${cid}" != "" ]; then
        result=$(sudo crictl inspect ${cid} 2>/dev/null | jq -r '.status.labels["io.kubernetes.pod.namespace"]+" "+.status.labels["io.kubernetes.pod.name"]' 2>/dev/null)
        if [ "${result}" != "" ]; then
          echo "${result}"
        else
          sudo crictl inspectp ${cid} 2>/dev/null | jq -r '.status.labels["io.kubernetes.pod.namespace"]+" "+.status.labels["io.kubernetes.pod.name"]' 2>/dev/null
        fi
      fi
    else
      result=$(ctr -n k8s.io c info ${cid} 2>/dev/null | jq -r '.Labels["io.kubernetes.pod.namespace"]+" "+.Labels["io.kubernetes.pod.name"]' 2>/dev/null)
      if [ "${result}" != "" ]; then
        echo "${result}"
      else
        ctr c ls 2>/dev/null | grep ${cid} 2>/dev/null | awk '{print $2}' 2>/dev/null
      fi
    fi
  fi
}

```


# CRI-O
```bash
# 查看当前生效的配置
crio-status config  | grep -i pid
```

## 统计容器可读可写层存储用量
```bash
for config in $(ls /var/lib/containers/storage/overlay-containers/*/userdata/config.json)
do
  diff=$(cat $config 2>/dev/null | jq .root.path -r|sed 's/merged$/diff/g')
  du -s $diff
done | awk '{s+=$1} END {print s}'
```

## 指定seccomp profile
```bash
# /etc/crio/crio.conf
[crio.runtime]
seccomp_profile = "/etc/crio/seccomp.json"
```

通过配置空的`seccomp.json`文件，放开所有限制：
```bash
# cat /etc/crio/seccomp.json
{}
```

## 容器存储目录
* `/run/containers/storage/overlay-containers/<pod-sandbox>/userdata/`，放置这个pod的`hostname`和`resolv.conf`等。
* `/run/containers/storage/overlay-containers/<container>/userdata/`，放置容器的配置文件、挂载点等。

## non-root用户使用devices
参见 [non-root-containers-and-devices](https://kubernetes.io/blog/2021/11/09/non-root-containers-and-devices/) 。

```bash
# 修改crio配置，开启 device_ownership_from_security_context
cat << EEOOFF > /etc/crio/crio.conf.d/10-device-ownership
[crio.runtime]
device_ownership_from_security_context = true
EEOOFF

# 重启crio使配置生效
systemctl restart crio

# 检查配置生效
crio-status c | grep device_ownership_from_security_context
```

## 检查容器存储数据量是否合理
overlay元数据中id数：
```bash
sudo cat /var/lib/containers/storage/overlay-layers/layers.json /var/lib/containers/storage/overlay-layers/volatile-layers.json | jq . | grep -c "id\""
```

和`/var/lib/containers/storage/overlay`目录下文件夹数（除`l`文件夹外）是否接近：
```bash
sudo ls /var/lib/containers/storage/overlay | wc -l
```

参考链接[cri-o/issues/6981](https://github.com/cri-o/cri-o/issues/6981#issuecomment-1608606437)

## 问题debug
**调整日志级别**：
```bash
# 修改日志级别log_level为info、debug或trace
/etc/crio/crio.conf.d/00-default

# 重载配置
systemctl reload crio
```

**获取pprof数据**：
```bash
# 通过环境变量，指定开启pprof
Environment="ENABLE_PROFILE_UNIX_SOCKET=true"

# 获取pprof数据，例如goroutine
curl --unix-socket /var/run/crio/crio.sock http://localhost/debug/pprof/goroutine?debug=1

# 当crio不响应时获取goroutine调用栈，调用栈信息保存在 /tmp/crio-goroutine-stacks-* 文件
systemctl kill -s USR1 crio.service
```

**通过unix socket直接调用API**：
```bash
# 查询容器详情
curl --unix-socket /var/run/crio/crio.sock http://localhost/containers/{CONTAINER_ID}
```

## Deep Dive
### 创建容器
创建容器核心逻辑在`createSandboxContainer()`。

cri server -> conmon -> runc -> user container process

### 列出镜像ImageService/ListImages
以`/runtime.v1alpha2.ImageService/ListImages`为例，`storage/storage_transport.go`中会从容器存储中，解析对应的镜像信息并返回。

核心逻辑在`ParseStoreReference()`的`parsed reference into`。

# podman
## 配置管理
* 配置文件在`/usr/share/containers/`和`/etc/containers/`。
* 默认seccomp策略文件路径`/usr/share/containers/seccomp.json`。

## 使用podman查看cri创建的pod
```bash
podman ps --all --external
podman ps --all --storage
```

## 容器镜像和overlay/layer对应关系
1. `podman images`看到的镜像ID(`IMAGE ID`)即本地缓存镜像的id，具体对应于`/var/lib/containers/storage/overlay-images`目录下一个个文件夹
2. `/var/lib/containers/storage/overlay-images/*/manifest`中有容器镜像的`layer`信息及每一层的大小
3. ???

## 在login后podman的认证信息可能存放的几个地方
1. Linux默认在`${XDG_RUNTIME_DIR}/containers/auth.json`，即例如`/run/user/0/containers/auth.json`
2. Windows和macOS默认在`$HOME/.config/containers/auth.json`
3. 若缺失上述文件，则继续检查`$HOME/.docker/config.json`，即兼容使用`docker login`认证信息

## 创建manifest list支持多架构镜像
```bash
# 新建一个manifest list
podman manifest create localhost/flannel:v0.23.0
# 向manifest list中添加镜像
podman manifest add localhost/flannel:v0.23.0 foo.bar/dev/flannel:v0.23.0-amd64 foo.bar/dev/flannel:v0.23.0-arm64
# 【可选】查看manifest list中镜像列表，检查各镜像携带的arch、variant、os等信息
podman manifest inspect localhost/flannel:v0.23.0
# 【可选】如果镜像没有arch信息，需要通过annotate为镜像添加arch等信息
podman manifest annotate --arch "amd64" localhost/flannel:v0.23.0 foo.bar/dev/flannel:v0.23.0-amd64
podman manifest annotate --arch "arm64" localhost/flannel:v0.23.0 foo.bar/dev/flannel:v0.23.0-arm64
# 上传manifest list至镜像仓库
podman manifest push localhost/flannel:v0.23.0 foo.bar/dev/flannel:v0.23.0
```

## 常用命令
```bash
# 查看当前挂载的容器镜像
podman image mount

# 挂载容器镜像
podman image mount  quay.io/openshift-scale/etcd-perf:latest

# 卸载容器镜像
podman image unmount quay.io/openshift-scale/etcd-perf:latest

# 查看镜像详情
cat /var/lib/containers/storage/overlay-images | jq

# 调整日志级别
podman pull --authfile /path/to/config.json <image> --log-level debug

# 启容器但不分配网络
podman run -it --rm --net=none centos:latest bash
```

# crictl
_crictl_ 访问*cri server*，同kubelet的行为一致，因此常用于站在kubelet角度去debug容器运行时。

## 直接创建容器
_crictl_ 拉起容器比*podman*等CLI工具麻烦，需要编辑json或yaml格式的配置文件，再拉起容器。而且，其行为同kubelet一致，因此拉起容器前还需要创建pod sandbox容器。

### 创建Pod Sandbox
sandbox配置文件`sandbox.json`如下：
```json
{
  "metadata": {
    "name": "sandbox",
    "namespace": "default",
    "attempt": 1,
    "uid": "xxx"
  },
  "hostname": "POD",
  "log_directory": "/tmp",
  "linux": {
    "security_context": {
      "privileged": true,
      "namespace_options": {
        "network": 2
      }
    }
  }
}
```

然后执行如下命令：
```bash
crictl runp sandbox.json
```

### 创建业务容器
业务容器配置文件`container.json`如下：
```json
{
    "metadata":{
        "name":"container",
        "attempt": 1
    },
    "image": {
        "image": "centos:latest"
    },
    "args": [
        "sleep", "inf"
    ],
    "mounts": [
        {"container_path":"/dev", "host_path":"/dev"},
        {"container_path":"/var/log", "host_path":"/var/log"}
    ],
    "log_path": "tmp.log",
    "linux": {
      "security_context": {
        "privileged": true
      }
    }
}
```

然后执行如下命令：
```bash
crictl create <sandbox-id> container.json sandbox.json
```

### 如何配置
参见`vendor/k8s.io/cri-api/pkg/apis/runtime/v1/api.pb.go`中`PodSandboxConfig`和`ContainerConfig`结构体定义。

**注意**和OCI的区别[opencontainers/runtime-spec](https://github.com/opencontainers/runtime-spec/specs-go/config.go) 。

## 查看容器资源用量

### 容器可读可写层存储占用top10
```bash
crictl stats -a -o json | jq '.stats[] | .writableLayer.usedBytes.value + " " + .attributes.labels["io.kubernetes.pod.namespace"] + " " + .attributes.labels["io.kubernetes.pod.name"] + " " + .attributes.id' -r | sort -rn | head -n 10
```

### 容器可读可写层inode占用top10
```bash
crictl stats -a -o json | jq '.stats[] | .writableLayer.inodesUsed.value + " " + .attributes.labels["io.kubernetes.pod.namespace"] + " " + .attributes.labels["io.kubernetes.pod.name"]' -r | sort -rn | head -n 10
```


# Docker

## 容器环境下的swap使用
为什么swap不适用于容器平台？我的理解：
* 有swap在，接近limit时容器内的进程会使用swap“腾出”部分内存，容器limit的限制就得不到遵守，这块同cgroups相关
* 容器环境下，虽然主机上内存资源充足，但是swap还是会使用，这与swap的设计初衷背道而驰的。
* 使用swap会严重影响io性能。

总结，swap是在容器崛起前的产物，当前出现的各类swap问题，归根到底需要swap（内存管理）和cgroup“协商”处理。

查询占用swap分区Top20的Pods
```bash
#!/bin/bash

for pid in $(top -b -n1 -o SWAP | head -n27 | sed '1,7d' | awk '{print $1}')
do
    p=${pid}
    while true
    do
        if [ ${p} = 1 -o ${p} = 0 ]; then
            break
        fi

        pp=$(ps -o ppid= ${p} | grep -Eo '[0-9]+')

        if [ ${pp} = 1 -o ${pp} = 0 ]; then
            break
        fi

        search=$(ps -ef | grep "\<${pp}\>" | grep 'docker-containerd-shim')
        if [ "${search}" = "" ]; then
            p=${pp}
            continue
        fi

        cid=$(echo ${search} | sed 's/.*docker-containerd-shim//g' | awk '{print $1}')
        cname=$(docker ps --no-trunc | grep ${cid} | awk '{print $NF}')
        if [ "${cname}" = "" ]; then
            break
        fi

        OLD_IFS="$IFS"
        IFS="_"
        infos=(${cname})
        IFS="${OLD_IFS}"
        echo "Pid:$(printf "%6d" ${pid})    $(grep VmSwap /proc/${pid}/status)    Pod: ${infos[2]}"
        break
    done
done
```

## 深入docker stats命令
~~~
docker engine-api: func (cli *Client) ContainerStats
-> dockerd  src/github.com/docker/docker/daemon/stats.go:135   daemon.containerd.Stats(c.ID)
-> containerd   runtime/container.go   func (c *container) Stats() (*Stat, error)
-> runtime (docker-runc events --stats container-id)        runc/libcontainer/cgroups/fs/memory.go   func (s *MemoryGroup) GetStats(path string, stats *cgroups.Stats) error
-> cgroups (memory)

docker-runc events --stats 9c8ad7d4885e2601a76bc3e1a4883a48a1c83e50ab4b7205176055a6fd6ec548 | jq .data.memory
docker-runc events --stats 9c8ad7d4885e2601a76bc3e1a4883a48a1c83e50ab4b7205176055a6fd6ec548 | jq .data.memory.usage.usage
的值直接取自：
cat /sys/fs/cgroup/memory/kubepods/burstable/podaebd4ae8-8e1b-11e8-b174-3ca82ae95d28/9c8ad7d4885e2601a76bc3e1a4883a48a1c83e50ab4b7205176055a6fd6ec548/memory.usage_in_bytes
~~~


## Docker问题定位

### Docker卡死hang住
```bash
# 检查dockerd是否响应服务请求
curl --unix-socket /var/run/docker.sock http://v1.26/containers/json?all=1

# 线程调用栈输出至/var/run/docker文件夹
kill -SIGUSR1 <docker-daemon-pid>

# containerd调用栈输出至messages，也会输出文件至/tmp目录
kill -SIGUSR1 <containerd-pid>

# 获取containerd-shim堆栈，堆栈输出至 shim.stdout.log
# 注意，需要开启containerd-shim -debug
cat /var/lib/containerd/io.containerd.runtime.v1.linux/moby/<container-id>/shim.stdout.log
kill -SIGUSR1 <containerd-shim-pid>
```


## Docker操作

### 常用操作

```bash
docker system prune # 存储清理，可以加上参数 -a
docker system df    # 查看容器、镜像的存储用量
docker 重启是增加 live-restore 选项，可以降低重启docker的开销，重启docker daemon的时候容器不重启  除非bip这些变了。
docker push xxxx   # 将镜像push到私有registry，注意，nodeB希望从nodeA的registry获取镜像时，nodeA上必须先push到registry才行
docker pull xxxx   # 从registry上下载镜像至本地
docker run -it --name test --net container:1a9bfd40505e --entrypoint=/usr/bin/sh openstack-glance:RC2  # 共享容器网络，glance中携带tcpdump命令，可网络抓包
docker run -it --name test --net=host openstack-keystone:D1101 bash
docker rm -f $(docker ps | grep haproxy | awk '{print $1}')
docker run -it --net=host centos:base bash     # 共享HOST网络
docker stats --no-stream   # 查看容器状态、资源使用情况
docker run -d -p 881 -v /root/sample/website:/var/www/html/website:rw --privileged=true test-img:1.0 nginx # 映射时需要加--privileged=true防止没有权限
docker attach xxxx    # 绑定到容器的stdio
docker exec d8c875f38278 bash -c "echo '1.2.3.4 hehe' >> /etc/hosts"   # 进入容器执行命令
docker inspect -f "{{json .Mounts}}" b2aed79fec98
docker inspect ${container} --format '{{.State.Pid}}'    # 获取容器的entrypoint进程pid
docker stats --format "{{.Name}} {{.MemPerc}}"
docker images --format "{{.Repository}}:{{.Tag}}"
docker info -f '{{json .}}' | jq  #  格式化输出
docker load --input images.tar.gz
docker save myimage:latest | gzip > myimage_latest.tar.gz
curl -v -X POST http://<ip>:2375/v1.26/images/load -T xxx.tar    #  调用docker接口load容器镜像
```


### 提取镜像rootfs文件
```bash
docker export $(docker create busybox:1.0.0) > busybox.tar
mkdir rootfs
tar -C rootfs -xf busybox.tar
```


### docker build构建镜像
```bash
# 常规操作
docker build -t centos:base -f Dockerfile .

# 为容器镜像增加label的简便操作
echo "FROM centos:7" | docker build --label foo="bar" --label key="value" -t "centos:7-labeled" -
```


### 安装指定版本docker
操作如下：
```bash
yum -y install yum-utils
sudo yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
# 查看可安装docker版本
yum list docker-ce --showduplicates | sort -
yum install -y docker-ce-19.03.13-3.el7
systemctl enable docker.service
systemctl restart docker
```
也支持在既有`Containerd`的节点上，安装Docker。

### 关闭docker0
K8s集群网络插件打通容器网络，大多未使用`docker0`，另一方面`docker0`默认占用`172.17.0.1/16`网段，IP地址存在冲突可能，为此考虑关闭`docker0`。
注意，要让网络配置修改生效，必须先把容器全部停掉，具体操作如下：
1. `systemctl stop kubelet` 让kubelet停掉，不然它又会拉起容器
2. `docker stop $(docker ps -q)` 停止所有docker容器
3. 修改 `/etc/docker/daemon.json`，在其中增加`"bridge": "none"`将docker0网桥干掉
4. `systemctl restart docker` 重启docker服务
5. `systemctl start kubelet` 启动kubelet服务


### 修改容器的ulimit默认配置
在`/etc/docker/daemon.json`中增加`default-ulimits`，修改容器ulimit默认配置
```bash
# cat /etc/docker/daemon.json
{
  "default-ulimits": {
    "core": {
      "Name": "core",
      "Hard": 0,
      "Soft": 0
    }
  }
}
```
此后容器内不再输出`coredump`文件，进入容器后确认：
```bash
bash-4.4# cat /proc/$$/limits
Limit                     Soft Limit           Hard Limit           Units
...
Max core file size        0                    0                    bytes
...
```


### 使用docker-storage-setup初始化docker存储
节点上安装docker，并使用docker-storage-setup初始化docker存储。
docker-storage-setup仅依赖配置文件`/etc/sysconfig/docker-storage-setup`，会根据配置文件中的VG自动部署docker storage，包括：
1. 创建lv
2. 创建docker用的dm thin-pool
3. 为docker的thin-pool配置自动扩展（auto extend）
4. 为docker生成相应的存储配置（/etc/sysconfig/docker-storage）

docker-storage-setup实则软链接到`/usr/bin/container-storage-setup`。
`container-storage-setup`由RedHat开发，其目的为"This script sets up the storage for container runtimes"。
`container-storage-setup`内容可直接阅读脚本。
其配置文件路径为`/usr/share/container-storage-setup`，有效内容如下：
```bash
[root@zy-op-m224 ~]# cat /usr/share/container-storage-setup/container-storage-setup  | grep -v "^$\|^#"
STORAGE_DRIVER=devicemapper
DATA_SIZE=40%FREE
MIN_DATA_SIZE=2G
CHUNK_SIZE=512K
GROWPART=false
AUTO_EXTEND_POOL=yes
POOL_AUTOEXTEND_THRESHOLD=60
POOL_AUTOEXTEND_PERCENT=20
DEVICE_WAIT_TIMEOUT=60
WIPE_SIGNATURES=false
CONTAINER_ROOT_LV_SIZE=40%FREE
```


### 构建Docker镜像最佳实践（Alpine）
Dockerfile同Makefile类似，借助基础镜像和Dockerfile，能方便的制作出干净、内容可知的容器镜像，同`docker cp + commit`或`docker export`临时方法相比，采用Dockerfile更适合制作正式的、用于发布交付的镜像。

镜像过大导致：
1. 离线安装包过大；
2. 过大的安装包和镜像，传输、复制时间过长，系统部署时间显著增加；
3. 过大的镜像，还会消耗过多的容器存储资源。

针对上述问题，以HAProxy的alpine版镜像为例，根据其官方Dockerfile，介绍如何使用“alpine基础镜像+Dockerfile”方式，制作干净、小巧且够用的Docker镜像，简单归纳如下：
```Dockerfile
# 【可选】
# 设置环境变量，主要包括软件的版本信息和源码文件MD5校验数据
ENV VERSION 1.6
ENV MD5 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# 【可选】
# 安装alpine官方镜像没有，但后期需要使用的工具，以socat为例
RUN apk add --no-cache socat

# 【可选】
# 安装构建、编译工具，注意，在最后需要删除这些工具
RUN apk add --no-cache --virtual .build-deps gcc make binutils

# 【可选】
# 下载源码、编译、安装，并清除源码和中间文件
RUN wget -O source-file.tar.gz "http://www.hehe.org/path/to/source-file-${VERSION}.tar.gz"
RUN echo "$MD5 *source-file.tar.gz" | md5sum -c
RUN xxx #解压源文件、编译、安装、并删除源文件和中间文件

# 【可选】
# 删除.build-deps组中所有package
RUN apk del .build-deps


# 设置Docker的ENTRYPOINT和CMD
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg"]
```




### 强制删除容器

当`docker rm -f`无法删除容器时，可以找到容器的`docker-container-shim`进程，删除该进程可终结容器，但需关注容器对应的/dev/dm-xx设备。

### 找到容器使用的dm-xx设备
容器的运行时bundle信息在`/var/run/docker/libcontainerd/xxxxxcidxxxxx/config.json`中，使用如下命令
```bash
cat config.json | jq .root.path -r
/var/lib/docker/devicemapper/mnt/9a7cc2bf60a1b4b9cfc96212b24528c03f7d74b1eabaf640341348e82e61fd15/rootfs
```
其中`9a7cc2xxx`就是`devicemapper`设备的id，可通过`dmsetup info`查找到具体的`dm-xx`信息


### docker pull加速

```bash
# 在/etc/docker/daemon.json中配置
{
  "registry-mirrors": ["https://registry.docker-cn.com","https://3laho3y3.mirror.aliyuncs.com"]
}
# 然后重启dockerd
```

### docker使用代理

docker服务设置环境变量以使用代理（也可以直接修改docker.service）

```bash
mkdir /etc/systemd/system/docker.service.d
cat <<EOF >/etc/systemd/system/docker.service.d/http-proxy.conf
[Service]
Environment="HTTP_PROXY=http://127.0.0.1:30000/"
Environment="HTTPS_PROXY=http://127.0.0.1:30000/"
Environment="NO_PROXY=*.foo.bar,10.0.0.0/8,192.168.*.*"
EOF
systemctl daemon-reload
# 检查环境变量已配置
systemctl show --property Environment docker
# 重启docker使配置生效
systemctl restart docker
```

**注意**，在终端中设置代理时，采用小写，例如：
```
export https_proxy=http://192.168.58.1:8080/
export http_proxy=http://192.168.58.1:8080/
# 白名单方式，指定不代理的地址或域名
export no_proxy=*.local,10.0.0.0/8,192.168.*.*
```



### 容器文件系统使用率统计

```bash
umount /mnt 2> /dev/null
for dm in $(ls /dev/mapper/docker-253* | grep -v pool)
do
    mount ${dm} /mnt
    usage=$(stat -f -c '100-%a*%S/1024*100/10471424' /mnt | bc)
    umount /mnt
    dmid=$(echo ${dm} | sed 's/.*-//g')
    containerid=$(grep -rn ${dmid} /var/run/docker/libcontainerd/*/config.json | sed 's/\/config.json:1.*//g' | sed 's/.*libcontainerd\///g')
    containername=$(docker ps --no-trunc | grep ${containerid} | awk '{print $NF}')
    echo "${dm} $(printf "%3d%%" ${usage}) ${containername}" | grep -v "k8s_POD_"
done
```


### 强制重启Docker服务
**未经验证**：
```bash
systemctl stop docker
killall dockerd
systemctl start docker
```


# 镜像仓库和工具
## skopeo
常用命令
```bash
skopeo inspect docker://foo.bar/image:tag
skopeo list-tags docker://foo.bar/image
# 同步镜像的所有tag，当前还不支持多架构
skopeo sync --src docker --dest dir foo.bar/image /mnt/usb --tls-verify=false --preserve-digests

# 复制镜像
skopeo copy --dest-tls-verify=false docker://docker.io/image:v1 docker://my.registry.hehe/image:v1
# 支持所有架构
skopeo copy docker://foo.bar/image:tag dir:/mnt/usb --tls-verify=false --multi-arch=all --preserve-digests
```

### 镜像搬运工
```bash
skopeo login registry-1.docker.io -u <username> -p <password>
skopeo login image.foo.bar -u <username> -p <password> --tls-verify=false

i=centos:latest
skopeo copy --dest-tls-verify=false docker://docker.io/$i docker://image.foo.bar/dev/$i
```

### Windows环境上源码运行skopeo搬运镜像
```bash
# Windows上构建skopeo可执行文件
GOOS=windows GOARCH=amd64 go build -tags "containers_image_openpgp" -o bin/skopeo ./cmd/skopeo

# 增加 --override-os 搬运指定系统platform的镜像，例如 linux
# 增加 --insecure-policy 跳过容器安全策略检查 /etc/containers/policy.json
skopeo copy --dest-tls-verify=false docker://docker.io/$i docker://image.foo.bar/dev/$i --insecure-policy --override-os linux
```
