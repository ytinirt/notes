
# Table of contents

<!--ts-->
   * [Table of contents](#table-of-contents)
   * [Linux and OS](#linux-and-os)
      * [Kernel](#kernel)
         * [进程调度](#进程调度)
         * [进程间通信](#进程间通信)
            * [ipcs和ipcrm工具](#ipcs和ipcrm工具)
         * [IO调度器](#io调度器)
         * [系统缓存](#系统缓存)
            * [swap交换分区](#swap交换分区)
               * [常见操作](#常见操作)
               * [使用文件file创建swap分区](#使用文件file创建swap分区)
            * [pagecache页缓存](#pagecache页缓存)
            * [drop_caches清理缓存](#drop_caches清理缓存)
            * [更加积极的缓存刷新](#更加积极的缓存刷新)
         * [大页内存hugepages](#大页内存hugepages)
            * [预分配大页内存](#预分配大页内存)
               * [系统启动时分配大页内存](#系统启动时分配大页内存)
               * [系统运行时分配大页内存](#系统运行时分配大页内存)
               * [Kubernetes中Pod使用大页内存](#kubernetes中pod使用大页内存)
         * [NUMA](#numa)
         * [内核模块Module](#内核模块module)
         * [inotify](#inotify)
            * [inotify文件监控句柄数耗尽的解决办法](#inotify文件监控句柄数耗尽的解决办法)
            * [找到谁在使用inotify instance资源](#找到谁在使用inotify-instance资源)
            * [找到谁在使用inotify watch资源](#找到谁在使用inotify-watch资源)
            * [inotify-tools](#inotify-tools)
         * [sysctl和系统配置](#sysctl和系统配置)
            * [典型操作](#典型操作)
         * [D-Bus](#d-bus)
      * [Systemd](#systemd)
      * [Networks](#networks)
         * [常用操作](#常用操作)
         * [OpenvSwitch](#openvswitch)
         * [bridge网桥](#bridge网桥)
         * [iptables](#iptables)
            * [预置的chains](#预置的chains)
            * [table类型](#table类型)
            * [常用操作](#常用操作-1)
            * [实例](#实例)
            * [iptables-extensions](#iptables-extensions)
         * [conntrack](#conntrack)
            * [常用操作](#常用操作-2)
         * [组播](#组播)
         * [防火墙](#防火墙)
         * [固定网卡名称](#固定网卡名称)
            * [背景知识](#背景知识)
            * [操作方法](#操作方法)
      * [Storage](#storage)
         * [lvm和devicemapper](#lvm和devicemapper)
            * [常用命令](#常用命令)
            * [LVM XFS的扩容和缩容](#lvmxfs的扩容和缩容)
            * [LVM EXT4的扩容和缩容](#lvmext4的扩容和缩容)
            * [Docker使用devicemapper的操作步骤](#docker使用devicemapper的操作步骤)
         * [ISCSI存储](#iscsi存储)
            * [使用iscsiadm客户端](#使用iscsiadm客户端)
            * [iscsi存储典型操作流程](#iscsi存储典型操作流程)
            * [targetcli设置iscsi本地调试环境](#targetcli设置iscsi本地调试环境)
         * [FC存储](#fc存储)
         * [存储多路径](#存储多路径)
      * [File system](#file-system)
         * [内存文件系统](#内存文件系统)
         * [xfs文件系统](#xfs文件系统)
         * [samba](#samba)
         * [NFS](#nfs)
            * [搭建NFS测试环境](#搭建nfs测试环境)
            * [nfs问题定位手段](#nfs问题定位手段)
         * [webdav](#webdav)
      * [Operation &amp; Management](#operation--management)
         * [用户管理](#用户管理)
         * [系统资源限制](#系统资源限制)
            * [limits.conf资源限制](#limitsconf资源限制)
            * [systemd资源限制](#systemd资源限制)
         * [openssl和证书](#openssl和证书)
            * [生成根证书](#生成根证书)
            * [签发自签名证书](#签发自签名证书)
            * [极简命令操作](#极简命令操作)
            * [自动化操作](#自动化操作)
            * [根证书缺失导致TLS通信失败](#根证书缺失导致tls通信失败)
         * [远程安全终端openssh](#远程安全终端openssh)
            * [服务端sshd](#服务端sshd)
            * [客户端ssh](#客户端ssh)
            * [ssh免密登录](#ssh免密登录)
         * [使用gost配置隧道](#使用gost配置隧道)
         * [Alpine](#alpine)
            * [使用镜像源](#使用镜像源)
            * [下载软件包及其依赖到本地](#下载软件包及其依赖到本地)
            * [安装本地软件包](#安装本地软件包)
         * [Debian](#debian)
            * [添加仓库](#添加仓库)
         * [CentOS](#centos)
            * [常用操作](#常用操作-3)
            * [关闭coredump](#关闭coredump)
         * [主机资源监控](#主机资源监控)
            * [常用命令](#常用命令-1)
            * [lsof查看打开文件](#lsof查看打开文件)
            * [fuser查找资源使用](#fuser查找资源使用)
            * [netstat查看网络资源](#netstat查看网络资源)
         * [性能调优和问题定位](#性能调优和问题定位)
            * [CPU性能](#cpu性能)
               * [设置或提升CPU运行频率](#设置或提升cpu运行频率)
               * [解决pcc和acpi的bug导致的CPU降频问题](#解决pcc和acpi的bug导致的cpu降频问题)
            * [网络性能](#网络性能)
            * [IO性能](#io性能)
               * [ionice修改io优先级](#ionice修改io优先级)
               * [fio性能测试](#fio性能测试)
               * [iozone](#iozone)
         * [文件系统修复](#文件系统修复)
         * [软件包管理](#软件包管理)
            * [rpm](#rpm)
            * [yum](#yum)
         * [域名解析](#域名解析)
            * [nslookup](#nslookup)
         * [时钟同步](#时钟同步)
            * [ntp](#ntp)
               * [优化NTP](#优化ntp)
               * [手动执行集群内时间同步的操作](#手动执行集群内时间同步的操作)
               * [ntp服务自我保护](#ntp服务自我保护)
               * [常用命令和工具](#常用命令和工具)
            * [chronyd](#chronyd)
         * [如何Debug程序和进程](#如何debug程序和进程)
            * [pmap分析内存使用](#pmap分析内存使用)
            * [strace查看进程调用链](#strace查看进程调用链)
            * [pstack分析CPU异常高时堆栈信息](#pstack分析cpu异常高时堆栈信息)
            * [ldd查看可执行文件依赖库](#ldd查看可执行文件依赖库)
            * [abrtd自动报告bug](#abrtd自动报告bug)
            * [scanelf获取运行时依赖（动态链接库）](#scanelf获取运行时依赖动态链接库)
            * [time查看执行时间](#time查看执行时间)
            * [coredump分析](#coredump分析)
         * [文本、字节流编辑](#文本字节流编辑)
         * [L2TP without IPsec配置](#l2tp-without-ipsec配置)
         * [日志](#日志)
            * [shell脚本使用logger输出日志](#shell脚本使用logger输出日志)
            * [使用journalctl查看日志](#使用journalctl查看日志)
         * [其它技巧](#其它技巧)
   * [Docker and Containers](#docker-and-containers)
      * [cgroup](#cgroup)
         * [cgroup子系统](#cgroup子系统)
         * [挂载cgroupfs](#挂载cgroupfs)
         * [常用操作](#常用操作-4)
      * [namespaces](#namespaces)
         * [常用工具](#常用工具)
            * [lsns](#lsns)
            * [nsenter](#nsenter)
            * [unshare](#unshare)
      * [容器安全](#容器安全)
         * [Discretionary Access Control](#discretionary-access-control)
         * [linux capabilities](#linux-capabilities)
         * [seccomp](#seccomp)
         * [selinux](#selinux)
      * [Docker操作](#docker操作)
         * [常用操作](#常用操作-5)
         * [强制删除容器](#强制删除容器)
         * [找到容器使用的dm-xx设备](#找到容器使用的dm-xx设备)
         * [Debug](#debug)
         * [docker pull加速](#docker-pull加速)
         * [docker使用代理](#docker使用代理)
         * [容器文件系统使用率统计](#容器文件系统使用率统计)
   * [Kubernetes](#kubernetes)
      * [操作实例](#操作实例)
         * [常见操作](#常见操作-1)
         * [客户端访问集群时context配置](#客户端访问集群时context配置)
         * [ConfigMap使用](#configmap使用)
         * [日志相关配置](#日志相关配置)
         * [提升集群HA性能](#提升集群ha性能)
         * [强制删除Pod](#强制删除pod)
         * [Pod中获取PodIP的方法](#pod中获取podip的方法)
         * [emptyDir在宿主机上的路径](#emptydir在宿主机上的路径)
         * [FC存储多路径的PV配置](#fc存储多路径的pv配置)
   * [Golang](#golang)
      * [常用操作](#常用操作-6)
   * [Special column](#special-column)
      * [Git](#git)
         * [常用操作](#常用操作-7)
      * [Makefile](#makefile)
         * [Makefile文件](#makefile文件)
         * [cmake](#cmake)
      * [Etcd](#etcd)
         * [v3常见操作](#v3常见操作)
         * [v2 API](#v2-api)
         * [修复故障节点](#修复故障节点)
         * [快照备份（v3 支持）](#快照备份v3支持)
         * [v2全量备份](#v2全量备份)
         * [调优](#调优)
         * [错误类型说明](#错误类型说明)
      * [tcpdump](#tcpdump)
         * [tcpdump和libpcap常用规则](#tcpdump和libpcap常用规则)
      * [Openstack](#openstack)
         * [常用操作](#常用操作-8)
         * [nova compute健康状态检查](#nova-compute健康状态检查)
         * [rally测试中TCP端口耗尽问题解决](#rally测试中tcp端口耗尽问题解决)
      * [OpenShift and OKD](#openshift-and-okd)
         * [常用操作](#常用操作-9)
         * [官方yum源](#官方yum源)
      * [Harbor](#harbor)
         * [手动清理镜像](#手动清理镜像)
      * [Rancher](#rancher)
         * [通过API访问Rancher](#通过api访问rancher)
         * [在Air Gap环境中以HA方式部署Rancher](#在air-gap环境中以ha方式部署rancher)
      * [nginx](#nginx)
      * [haproxy](#haproxy)
         * [使用socat操作UNIX domain套接字](#使用socat操作unix-domain套接字)
      * [keepalived](#keepalived)
         * [keepalived背后的vrrp](#keepalived背后的vrrp)
      * [Swagger](#swagger)
         * [使用swagger-ui](#使用swagger-ui)
      * [memcached](#memcached)
      * [mysql](#mysql)
         * [数据库操作](#数据库操作)
            * [常用操作](#常用操作-10)
            * [数据库master节点操作](#数据库master节点操作)
            * [数据库slave节点操作](#数据库slave节点操作)
            * [重置slave上master binlog的位置](#重置slave上master-binlog的位置)
            * [数据库读写分离主从同步延迟测试SQL语句](#数据库读写分离主从同步延迟测试sql语句)
            * [查看从数据库服务器信息](#查看从数据库服务器信息)
         * [DBA相关](#dba相关)
            * [获取 InnoDB_Buffer_Pool_Size 推荐值](#获取-innodb_buffer_pool_size-推荐值)
            * [获取 InnoDB Buffer Pool实际使用情况](#获取-innodb-buffer-pool实际使用情况)
            * [获取pool size 和 数据库内存使用参考值（mysql在800连接但不执行任何sql时需要的内存）](#获取pool-size-和-数据库内存使用参考值mysql在800连接但不执行任何sql时需要的内存)
            * [查询临时表的创建](#查询临时表的创建)
            * [临时表使用的内存大小](#临时表使用的内存大小)
            * [mysqld内存高使用量分析](#mysqld内存高使用量分析)
         * [SQL语句实例](#sql语句实例)
      * [maxscale](#maxscale)
      * [mha](#mha)
      * [PostgreSQL](#postgresql)
      * [SQLite](#sqlite)
      * [Redis](#redis)
      * [RabbitMQ](#rabbitmq)
      * [influxdb](#influxdb)
      * [Prometheus](#prometheus)
      * [Weavescope](#weavescope)
      * [Ceph](#ceph)
      * [KVM](#kvm)
         * [virsh操作](#virsh操作)
      * [drbd](#drbd)
         * [drbd常见命令](#drbd常见命令)
         * [修复处于Diskless状态的节点](#修复处于diskless状态的节点)
         * [修复脑裂/standalone状态的节点](#修复脑裂standalone状态的节点)
         * [修复Inconsistent/Inconsistent状态](#修复inconsistentinconsistent状态)
         * [肉搏操作drbd存储](#肉搏操作drbd存储)
         * [drbd周边知识](#drbd周边知识)
            * [块设备操作命令](#块设备操作命令)
            * [如何判断块设备是否在被使用中](#如何判断块设备是否在被使用中)
            * [debugfs](#debugfs)
      * [ansible](#ansible)
      * [YAML](#yaml)
      * [JSON](#json)
         * [JSON Patch](#json-patch)
            * [简单示例](#简单示例)
            * [实用例子](#实用例子)
            * [操作说明](#操作说明)
         * [常用操作](#常用操作-11)
      * [base64](#base64)
      * [Shell脚本](#shell脚本)
         * [Bash实例](#bash实例)
            * [循环](#循环)
            * [获取入参名称及值](#获取入参名称及值)
            * [字符串转array和array切片](#字符串转array和array切片)
            * [trap](#trap)
            * [字符串切片](#字符串切片)
            * [截取字符串子串](#截取字符串子串)
            * [字符串比较](#字符串比较)
            * [计算数组中元素个数](#计算数组中元素个数)
            * [当没有stress时如何对CPU施压](#当没有stress时如何对cpu施压)
            * [并发执行多任务](#并发执行多任务)
            * [替换变量](#替换变量)
            * [日志输出：](#日志输出)
            * [检查文件是否存在](#检查文件是否存在)
            * [IFS指定分隔符](#ifs指定分隔符)
            * [遍历处理被IFS分隔过的数组](#遍历处理被ifs分隔过的数组)
            * [从文件中读取信息](#从文件中读取信息)
            * [比较两个变量是否相同](#比较两个变量是否相同)
            * [高级test语句: 正则表达式，判断是否为纯数字](#高级test语句-正则表达式判断是否为纯数字)
            * [判断一个文件夹是否为空](#判断一个文件夹是否为空)
            * [使用cat生成文件](#使用cat生成文件)
            * [运算](#运算)
         * [其它记录](#其它记录)
      * [Java](#java)
         * [Debug Java](#debug-java)
      * [Python](#python)
         * [使用pip](#使用pip)
         * [实例](#实例-1)
            * [字符串操作](#字符串操作)
      * [正则表达式Regex](#正则表达式regex)
   * [Memo and Skills](#memo-and-skills)
      * [宿主机上直接修改容器内文件](#宿主机上直接修改容器内文件)
      * [vi/vim](#vivim)
         * [常用操作](#常用操作-12)
      * [奇技淫巧](#奇技淫巧)

<!-- Added by: zy, at: Sun Feb 16 12:55:14 CST 2020 -->

<!--te-->


# Linux and OS



## Kernel



### 进程调度

migration是Linux内核进程，用于在core间分摊处理压力：

```bash
[zy@m1 ~]$ ps -ef | grep migration
root         7     2  0 Feb02 ?        00:00:14 [migration/0]
root        12     2  0 Feb02 ?        00:00:14 [migration/1]
```



### 进程间通信

#### ipcs和ipcrm工具

```bash
# 文件/etc/sysctl.conf中配置信号量相关参数
	kernel.msgmni
	kernel.sem

cat /proc/sys/kernel/sem
echo 250 32000 100 128 > /proc/sys/kernel/sem
ipcs -ls
sysctl -w kernel.sem="250 32000 100 128"
echo "kernel.sem=250 32000 100 128" >> /etc/sysctl.conf
```



### IO调度器

参见:

* [Archlinux Improving Performance](https://wiki.archlinux.org/index.php/Improving_performance#Input/output_schedulers)
* [Linux-I-O-Schedulers](http://www.admin-magazine.com/HPC/Articles/Linux-I-O-Schedulers)
* [Ubuntu IOSchedulers](https://wiki.ubuntu.com/Kernel/Reference/IOSchedulers)

修改/查看设备当前调度器

```bash
echo 'deadline' > /sys/block/sda/queue/scheduler
cat /sys/block/sda/queue/scheduler
```

引导时修改默认调度器

1. 在`/etc/default/grub`中，为`GRUB_CMDLINE_LINUX`增加配置`elevator=deadline`
2. 重新生成配置文件:

  - BIOS节点上，执行`grub2-mkconfig -o /boot/grub2/grub.cfg`
  - UEFI节点上，执行`grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg`



### 系统缓存

#### swap交换分区

##### 常见操作

制作swap分区并使用新的swap分区

```bash
mkswap /dev/hdb1
swapon /dev/hdb1
```
启机时需要自动挂载swap分区，修改/etc/fstab文件，增加swap分区的配置:

```bash
/dev/hdb1    none    swap   sw   0   0
```
查看交换分区类型

```bash
swapon -s
```
关闭Swap交换分区

```bash
# 先强制释放系统缓存
echo 3 > /proc/sys/vm/drop_caches
echo 0 > /proc/sys/vm/drop_caches
# 再关闭Swap交换分区
swapoff /dev/mapper/centos-swap
```
另一种关闭Swap交换分区的方法
```bash
# 执行该命令后，系统会逐渐回收swap分区的空间，通过free命令看到swap分区的在变小
swapoff -a
```
打开所有的交换分区（将/etc/fstab中的swap空间都挂载上）

```bash
swapon -a
```
查看进程的Swap分区使用情况

```bash
cat /proc/pid/smaps
cat /proc/pid/status | grep -i vm
top ->f->选择显示Swap    ->f->s  选择排序的项
top -b -n1 -o SWAP | head -n27 | sed '1,7d'    # TOP 20交换分区使用
```
设置Swap分区使用偏好

```bash
echo 30 > /proc/sys/vm/swappiness
```
##### 使用文件file创建swap分区
创建一个16GB的swap文件
```bash
dd if=/dev/zero of=/swapfile bs=1G count=16
```
初始化swap文件
```bash
mkswap /swapfile
chmod 0600 /swapfile
```
挂载并使用swap文件
```bash
swapon /swapfile
```
需要启机自动挂载swap文件时，在/etc/fstab中增加如下配置：
```bash
/swapfile    none    swap   sw   0   0
```



#### pagecache页缓存



#### drop_caches清理缓存

通过`/proc/sys/vm/drop_caches`(since Linux 2.6.16)清理系统缓存

>Writing to this file causes the kernel to drop clean caches, dentries and inodes from memory, causing that memory to become free.
>
>To free pagecache, use `echo 1 > /proc/sys/vm/drop_caches`
>
>To free dentries and inodes, use `echo 2 > /proc/sys/vm/drop_caches`
>
>To free pagecache, dentries and inodes, use `echo 3 > /proc/sys/vm/drop_caches`
>
>Because this is a nondestructive operation and dirty objects are not freeable, the user should run sync(8) first.



#### 更加积极的缓存刷新

```bash
# 默认值
[root@zy-m224 scripts]# sysctl -a 2>/dev/null | grep vm.dirty
vm.dirty_background_bytes = 0
vm.dirty_background_ratio = 10
vm.dirty_bytes = 0
vm.dirty_expire_centisecs = 3000
vm.dirty_ratio = 30
vm.dirty_writeback_centisecs = 500
vm.dirtytime_expire_seconds = 43200

# 优化值
vm.dirty_background_ratio = 1
vm.dirty_ratio = 1
vm.dirty_expire_centisecs = 10
vm.dirty_writeback_centisecs = 10
```



### 大页内存hugepages

#### 预分配大页内存
参见资料[CONFIGURING HUGETLB HUGE PAGES](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/performance_tuning_guide/sect-red_hat_enterprise_linux-performance_tuning_guide-memory-configuring-huge-pages)

##### 系统启动时分配大页内存
TODO

##### 系统运行时分配大页内存
通过 `/sys/devices/system/node/<node_id>/hugepages/hugepages-<size>/<nr_hugepages>` 指定NUMA节点`node_id`上分配页大小`hugepages-<size>`的大页内存`<nr_hugepages>`个。
```bash
# numastat -cm | egrep 'Node|Huge'
                 Node 0 Node 1 Node 2 Node 3  Total add
AnonHugePages         0      2      0      8     10
HugePages_Total       0      0      0      0      0
HugePages_Free        0      0      0      0      0
HugePages_Surp        0      0      0      0      0
# echo 20 > /sys/devices/system/node/node2/hugepages/hugepages-2048kB/nr_hugepages
# numastat -cm | egrep 'Node|Huge'
                 Node 0 Node 1 Node 2 Node 3  Total
AnonHugePages         0      2      0      8     10
HugePages_Total       0      0     40      0     40
HugePages_Free        0      0     40      0     40
HugePages_Surp        0      0      0      0      0
```

##### Kubernetes中Pod使用大页内存
参见[资料](https://kubernetes.io/docs/tasks/manage-hugepages/scheduling-hugepages/)



### NUMA

常见操作：

```bash
numactl -H
numastat
```





### 内核模块Module

启机时自动加载内核驱动的方法可参见`man modules-load.d`。

检查模块已被静态编译到内核中：

```bash
grep -e ipvs -e nf_conntrack_ipv4 /lib/modules/$(uname -r)/modules.builtin
```



### inotify

#### inotify文件监控句柄数耗尽的解决办法

```bash
fs.inotify.max_user_watches = 1000000
```

#### 找到谁在使用inotify instance资源

```bash
for foo in /proc/*/fd/*; do readlink -f $foo; done | grep inotify | sort | uniq -c | sort -nr
find /proc/*/fd/* -type l -lname 'anon_inode:inotify' -print
find /proc/*/fd -lname anon_inode:inotify | cut -d/ -f3 | xargs -I '{}' -- ps --no-headers -o '%p %U %c' -p '{}' | uniq -c | sort -nr
```

#### 找到谁在使用inotify watch资源

从代码看，watches的使用数量是统计到每个用户user（uid）的，因此无法找到是那个进程（线程）耗尽了inotify watch资源。
详见Linux内核代码 `fs/notify/inotify/inotify_user.c`:

```c
inotify_new_watch()
  atomic_inc(&group->inotify_data.user->inotify_watches);
```

#### inotify-tools

```bash
inotifywait
inotifywatch
```



### sysctl和系统配置

#### 典型操作

设置浮动IP时，需要让haproxy监听非本地IP地址（即VIP地址），在
```bash
/etc/sysctl.conf
```
中增加配置
```bash
net.ipv4.ip_nonlocal_bind=1
```
然后使用如下命令使其生效
```bash
sysctl -p
```
获取系统支持的最大线程数：
```bash
sysctl kernel.pid_max
```
修改系统支持的最大线程数：
```bash
sysctl -w kernel.pid_max=327680
```

防止well-known端口被当做local port占用

```bash
net.ipv4.ip_local_reserved_ports = 35357,12345
```

系统层面的，能够打开的文件总数

```bash
/proc/sys/fs/file-max
```



### D-Bus

```bash
busctl
```





## Systemd

常用操作

```bash
systemctl status etcd2.service
systemctl status gocronitor --lines=0  # 不要过多的输出
systemctl start docker
systemctl stop docker
systemctl restart docker
systemctl enable docker                # Service会在设备上自动启用
systemctl disable docker
systemctl show docker -p xxx           # 显示详细配置和属性
systemctl is-active kube-kubelet.service
systemctl list-dependencies etcd2      # 查看“etcd2”依赖谁
systemctl list-dependencies etcd2 --reverse # 查看谁依赖“etcd2”
```

service文件中：

```bash
"--etcd-certfile=\${ETCD_CLIENT_PEM}"   # 使用反斜杠'\'对'$'转义
```



## Networks

### 常用操作

```bash
ip route add 0.0.0.0/0 via 172.25.0.1
ip -4 route get 8.8.8.8 # 获取生效的默认路由及其出接口IP地址
cat /proc/net/route && cat /proc/net/ipv6_route   # 当没有ip和route命令时查看路由信息
ip address add 172.25.50.32/20 dev eth0 # 设置（secondary）地址
arp -s 172.25.50.31 fa:16:3e:b7:2a:8e # 添加静态ARP表项
arp -d 172.25.50.31     # 删除ARP表项
```



### OpenvSwitch

常用命令：

```bash
ovs_dbg_listports
```



### bridge网桥

常用操作：

```bash
bridge fdb show dev flannel.1           # 查看FDB表中与flannel.1相关的表项。
brctl                                   # 属于bridge-utils包
```





### iptables

#### 预置的chains

~~~
PREROUTING   FORWARD   POSTROUTING
INPUT                  OUTPUT
~~~

#### table类型

* filter
* nat
* mangle
* raw
* security

#### 常用操作

```bash
iptables-save           # dump所有的规则，这些规则可直接使用
iptables -S -t nat      # 显示nat规则
iptables -S -t <filter | nat | mangle | raw | security> # 显示各个table的规则
iptables -t nat -D POSTROUTING -s 10.101.94.0/24 ! -o docker0 -j MASQUERADE  #删除Docker添加的源地址伪装规则
iptables -t nat -nL | less      #查看nat表在所有chain的规则
iptables -t nat -nL --line-numbers | less
iptables -t nat -D POSTROUTING 1
iptables -t nat -R KUBE-MARK-MASQ 1 -j MARK --set-xmark 0x2000/0x2000
iptables -A INPUT -s 172.25.19.177 -p tcp --dport 8888 -j ACCEPT    # 添加规则
iptables -nL --line-numbers     # 显示INPUT、FORWARD、OUTPUT等chain上的规则，带规则号rulenum
iptables -D INPUT 8             # 删除INPUT chain上的第8号规则
iptables -A IN_public_allow -p tcp -m tcp --dport 8080 -m conntrack --ctstate NEW -j ACCEPT   # CentOS自定义filter chain上增加accept规则
# 限制节点间网络通信
iptables -I INPUT 1 -s <存储服务器IP地址> -p tcp -j DROP
iptables -D INPUT -s <存储服务器IP地址> -p tcp -j DROP
```

注意，配置`POSTROUTING chain`时，需要指定具体的`table`。

#### 实例

对于应用直接在节点上启动占用的端口，为了整洁起见，专门建立链：

```bash
iptables -N DEMOINPUT
# 将所有允许通过的原地址通过这种方式加入
iptables -A DEMOINPUT -s 172.25.18.24 -p tcp -m tcp --dport 8888 -j RETURN
iptables -A DEMOINPUT -s 172.25.18.41 -p tcp -m tcp --dport 8888 -j RETURN
iptables -A DEMOINPUT -s 172.25.18.89 -p tcp -m tcp --dport 8888 -j RETURN
iptables -A DEMOINPUT -s 127.0.0.1 -p tcp -m tcp --dport 8888 -j RETURN
# 将其它访问此端口的报文丢弃
iptables -A DEMOINPUT -p tcp -m tcp --dport 8888 -j DROP
iptables -I INPUT 1 -j DEMOINPUT
```

对于使用 docker、K8s的nodeport运行起来占用的端口，为了整洁起见，专门建立链：

```bash
iptables -N DEMOFORWARD
# 将所有允许通过的原地址通过这种方式加入
iptables -A DEMOFORWARD -s 172.25.18.24/32 -p tcp -m tcp --dport 3306 -j RETURN
iptables -A DEMOFORWARD -s 172.25.18.41/32 -p tcp -m tcp --dport 3306 -j RETURN
iptables -A DEMOFORWARD -s 172.25.18.89/32 -p tcp -m tcp --dport 3306 -j RETURN
iptables -A DEMOFORWARD -s 127.0.0.1/32 -p tcp -m tcp --dport 3306 -j RETURN
# 将其它访问此端口的报文丢弃
iptables -A DEMOFORWARD -p tcp -m tcp --dport 3306 -j DROP
iptables -I FORWARD 1 -j DEMOFORWARD
```

恢复：

```bash
# 将我们自建的链条内容清空
iptables -F DEMOINPUT
# 将我们的链条从主链上删除
iptables -D INPUT -j DEMOINPUT
# 删除我们的chain
iptables -X DEMOINPUT
```



#### iptables-extensions

扩展的iptables：

```bash
# 通过扩展的iptables规则，去屏蔽掉所有源地址不是172.17.8.1的、原始访问端口12380的请求
iptables -I DOCKER -m conntrack --ctstate DNAT ! --ctorigsrc 172.17.8.1/32 --ctorigdstport 12380 -j REJECT

# 数据库黑名单功能
iptables -N MYSQL3306
iptables -A MYSQL3306 -m conntrack --ctstate DNAT --ctorigsrc 10.125.30.150/32 --ctorigdstport 3306 -j REJECT
iptables -I FORWARD 1 -j MYSQL3306
```



### conntrack

#### 常用操作

```bash
# 查看SYN状态的连接
watch -n 0.5 -d 'cat /proc/net/nf_conntrack | grep -v "udp" | grep 35357 | grep SYN'
# 抓取SYN包
tcpdump -i ens160 "host 172.25.18.91 and port 35357" -nnl | grep "\[S"
```





### 组播

```bash
ipmaddr show dev ens192   				# 查看接口上的组播地址
ipmaddr add 33:33:00:00:00:02 dev eth0  # 添加静态组播地址
ipmaddr del 33:33:00:00:00:02 dev eth0  # 删除静态组播地址
```



### 防火墙

命令`firewall-cmd`



### 固定网卡名称

#### 背景知识

CentOS7在网卡的命名上使用了新的动态命名规则，已保证网卡名称是固定且可预测的，具体如下：

1. 依据Firmware或BIOS提供的设备索引号为网卡命名，如eno1。如不符合，则使用规则2。
2. 依据Firmware或BIOS提供的PCI-E 热插拔槽（slot）索引号为网卡命名，如ens1。如不符合，则使用规则3。
3. 使用硬件连接器或物理位置命名，如enp2s0。如不符合，则使用规则5。
4. 使用MAC地址命名，如en00abddedddee。默认不使用该规则
5. 使用默认的不可预期的kernel命名方式，如eth0。

#### 操作方法

修改 `/lib/udev/rules.d/60-net.rules` ，在原规则之前插入如下规则：
```bash
ACTION=="add", SUBSYSTEM=="net", DRIVERS=="?*", ATTR{address}=="0c:da:41:1d:e3:41", NAME="eth0"
```
其中`ATTR{address}==`后跟该网卡的MAC地址，`NAME=`为欲固定的网卡名称。

## Storage



### lvm和devicemapper

#### 常用命令
```bash
dmsetup info
dmsetup table
dmsetup table centos-data (设备id 253:3)
  0 975495168 linear 252:4 701351936
  |- 起始Sector号    |- 块设备id
    |- 结束Sector号        |- 块设备上起始Sector索引号
              |- 直接映射块设备
dmsetup table docker-253:0-13763296-pool (设备id 253:4)
  0 975495168 thin-pool 253:2 253:3 128 32768 1 skip_block_zeroing
  |- 起始Sector号       |- meta文件的设备id     |- 附件参数，表示略过用0填充的block
    |- 结束Sector号           |- data文件的设备id
              |- 创建的pool         |- 最小可分配的Sector数
                                        |- 最少可用Sector数的water mark，也就是threshold
                                              |- 代表有附加选项
dmsetup table docker-253:0-13763296-b89d0dbfcd280497532976e070e53a135cc56d0a2782dcc6f193bf28449c4919 (设备id 253:5)
  0 20971520 thin 253:4 8
  |- 起始Sector号       |- thin-provision设备标识符（24bits的数字）
    |- 结束Sector号
             |- 创建的thin
                  |- 用的pool的设备id
dmsetup ls
dmsetup status
dmsetup remove <device_name>
pvdisplay -m
vgdisplay
lvm
lvdisplay
vgreduce
vgreduce --removemissing
vgscan
pvchange -x n /dev/sdb1
pvchange -x y /dev/sdb1
lvchange -an centos/data
lvchange -an centos/metadata
lvscan
vgscan
lvchange -ay centos/metadata
lvchange -ay centos/data
vgs --noheadings --nosuffix --units s -o vg_size centos
pvcreate /dev/vdxx      # 新建pv
vgextend <vgname> <pvdevice>    # 将pv加入vg

# Docker使用devicemapper的最简操作
vgname='centos'
lvcreate -L 5120M -n metadata ${vgname}
sleep 2
lvcreate -l +100%FREE -n data ${vgname}
sleep 2

# 删除lv
lvremove centos/metadata
lvremove centos/data
```

#### LVM+XFS的扩容和缩容

操作步骤如下：

1. 备份数据，备份`/home`目录下所有数据。
2. 卸载挂载点`umount /home/`
3. 调整（缩小）lv大小，重建文件系统并重新挂载
```bash
[root@zy-super-load /]# lvreduce --size 50G centos/home
  WARNING: Reducing active logical volume to 50.00 GiB.
  THIS MAY DESTROY YOUR DATA (filesystem etc.)
Do you really want to reduce centos/home? [y/n]: y
  Size of logical volume centos/home changed from 433.24 GiB (110910 extents) to 50.00 GiB (12800 extents).
  Logical volume centos/home successfully resized.
[root@zy-super-load /]# lvs
  LV   VG     Attr       LSize  Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  home centos -wi-a----- 50.00g
  root centos -wi-ao---- 50.00g
  swap centos -wi-ao---- 15.75g
[root@zy-super-load /]# mkfs.xfs /dev/mapper/centos-home -f
meta-data=/dev/mapper/centos-home isize=512    agcount=4, agsize=3276800 blks
         =                       sectsz=512   attr=2, projid32bit=1
         =                       crc=1        finobt=0, sparse=0
data     =                       bsize=4096   blocks=13107200, imaxpct=25
         =                       sunit=0      swidth=0 blks
naming   =version 2              bsize=4096   ascii-ci=0 ftype=1
log      =internal log           bsize=4096   blocks=6400, version=2
         =                       sectsz=512   sunit=0 blks, lazy-count=1
realtime =none                   extsz=4096   blocks=0, rtextents=0
[root@zy-super-load /]# mount /dev/mapper/centos-home /home/
```
4. 新建lv用于/root目录
```bash
[root@zy-super-load home]# lvcreate -l +60%FREE -n rootdir centos
  Logical volume "rootdir" created.
[root@zy-super-load home]# lvs
  LV      VG     Attr       LSize    Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  home    centos -wi-ao----   50.00g
  root    centos -wi-ao----   50.00g
  rootdir centos -wi-a----- <229.95g
  swap    centos -wi-ao----   15.75g
```
5. 初始化文件系统并挂载/root目录
```bash
[root@zy-super-load /]# mkfs.xfs /dev/mapper/centos-rootdir
meta-data=/dev/mapper/centos-rootdir isize=512    agcount=4, agsize=15069696 blks
         =                       sectsz=512   attr=2, projid32bit=1
         =                       crc=1        finobt=0, sparse=0
data     =                       bsize=4096   blocks=60278784, imaxpct=25
         =                       sunit=0      swidth=0 blks
naming   =version 2              bsize=4096   ascii-ci=0 ftype=1
log      =internal log           bsize=4096   blocks=29433, version=2
         =                       sectsz=512   sunit=0 blks, lazy-count=1
realtime =none                   extsz=4096   blocks=0, rtextents=0
[root@zy-super-load /]# mount /dev/mapper/centos-rootdir /root
```
注意向`/etc/fstab`追加表项：`/dev/mapper/centos-rootdir /root xfs defaults 0 0`
6. 剩余150GB用于扩展根文件系统
```bash
[root@zy-super-load home]# vgdisplay
  --- Volume group ---
  VG Name               centos
  System ID
  Format                lvm2
  Metadata Areas        1
  Metadata Sequence No  6
  VG Access             read/write
  VG Status             resizable
  MAX LV                0
  Cur LV                4
  Open LV               3
  Max PV                0
  Cur PV                1
  Act PV                1
  VG Size               <499.00 GiB
  PE Size               4.00 MiB
  Total PE              127743
  Alloc PE / Size       88498 / <345.70 GiB
  Free  PE / Size       39245 / 153.30 GiB
  VG UUID               6xdmlp-9Tj7-RX9E-cXGA-ahti-1Kum-kvcMD1
```
7. 扩展根文件系统
```bash
[root@zy-super-load ~]# lvs
  LV      VG     Attr       LSize    Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  home    centos -wi-ao----   50.00g
  root    centos -wi-ao----   50.00g
  rootdir centos -wi-ao---- <229.95g
  swap    centos -wi-ao----   15.75g
[root@zy-super-load ~]# lvextend -l +100%FREE centos/root
  Size of logical volume centos/root changed from 50.00 GiB (12800 extents) to 203.30 GiB (52045 extents).
  Logical volume centos/root successfully resized.
[root@zy-super-load ~]# lvs
  LV      VG     Attr       LSize    Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  home    centos -wi-ao----   50.00g
  root    centos -wi-ao----  203.30g
  rootdir centos -wi-ao---- <229.95g
  swap    centos -wi-ao----   15.75g
[root@zy-super-load ~]# xfs_growfs /
meta-data=/dev/mapper/centos-root isize=512    agcount=4, agsize=3276800 blks
         =                       sectsz=512   attr=2, projid32bit=1
         =                       crc=1        finobt=0 spinodes=0
data     =                       bsize=4096   blocks=13107200, imaxpct=25
         =                       sunit=0      swidth=0 blks
naming   =version 2              bsize=4096   ascii-ci=0 ftype=1
log      =internal               bsize=4096   blocks=6400, version=2
         =                       sectsz=512   sunit=0 blks, lazy-count=1
realtime =none                   extsz=4096   blocks=0, rtextents=0
data blocks changed from 13107200 to 53294080
[root@zy-super-load ~]# df -h
Filesystem                  Size  Used Avail Use% Mounted on
/dev/mapper/centos-root     204G  897M  203G   1% /
devtmpfs                     16G     0   16G   0% /dev
tmpfs                        16G     0   16G   0% /dev/shm
tmpfs                        16G  8.4M   16G   1% /run
tmpfs                        16G     0   16G   0% /sys/fs/cgroup
/dev/vda1                  1014M  143M  872M  15% /boot
tmpfs                       3.2G     0  3.2G   0% /run/user/0
/dev/mapper/centos-home      50G   33M   50G   1% /home
/dev/mapper/centos-rootdir  230G   33M  230G   1% /root
```

#### LVM+EXT4的扩容和缩容

操作步骤如下：

1. 扩展根文件系统lv大小
```bash
[root@zy-op-m Packages]# lvs
  LV          VG     Attr       LSize    Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  docker-pool centos twi-aot---  <72.51g             6.50   0.41                            
  log         centos -wi-ao----  <19.34g                                                    
  mysql       centos -wi-ao----   96.71g                                                    
  root        centos -wi-ao---- <183.76g                
[root@zy-op-m Packages]# lvextend -L +8G centos/root
  Size of logical volume centos/root changed from <183.76 GiB (47042 extents) to <191.76 GiB (49090 extents).
  Logical volume centos/root successfully resized.
[root@zy-op-m Packages]# lvs
  LV          VG     Attr       LSize    Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  docker-pool centos twi-aot---  <72.51g             6.50   0.41                            
  log         centos -wi-ao----  <19.34g                                                    
  mysql       centos -wi-ao----   96.71g                                                    
  root        centos -wi-ao---- <191.76g         
```
2. 扩展根文件系统
```bash
[root@zy-op-m Packages]# df -h
Filesystem                Size  Used Avail Use% Mounted on
...
/dev/mapper/centos-root   181G  9.7G  162G   6% /
...
[root@zy-op-m Packages]# resize2fs /dev/mapper/centos-root
resize2fs 1.42.9 (28-Dec-2013)
Filesystem at /dev/mapper/centos-root is mounted on /; on-line resizing required
old_desc_blocks = 23, new_desc_blocks = 24
The filesystem on /dev/mapper/centos-root is now 50268160 blocks long.
[root@zy-op-m Packages]# df -h
Filesystem                Size  Used Avail Use% Mounted on
...
/dev/mapper/centos-root   189G   11G  170G   6% /
...
```

#### Docker使用devicemapper的操作步骤

操作步骤如下：

1. 创建块设备：例如`/dev/sdb`
2. 创建PV：`pvcreate /dev/sdb`
3. 创建VG：`vgcreate docker /dev/sdb`
4. 查看VG：`vgdisplay docker #其中，VG名称为docker`
5. 创建pool：
```bash
# 数据LV占用VG的95%空间
lvcreate --wipesignatures y -n thinpool docker -l 95%VG
# 元数据LV占用VG的1%空间，剩余4%空间自动扩展
lvcreate --wipesignatures y -n thinpoolmeta docker -l 1%VG
```
6. 转换为thinpool：
```bash
lvconvert -y --zero n -c 512K --thinpool docker/thinpool --poolmetadata docker/thinpoolmeta
```
7. 配置thinpool池自动扩展：
```bash
cat <<EOF >/etc/lvm/profile/docker-thinpool.profile
activation {
  thin_pool_autoextend_threshold=80
  thin_pool_autoextend_percent=20
}
EOF
```
8. 应用配置到docker/thinpool
```
lvchange --metadataprofile docker-thinpool docker/thinpool
```
9. 状态检查
```bash
lvs -o+seg_monitor
```
10. dockerd配置
```bash
--storage-driver=devicemapper --storage-opt dm.datadev=/dev/centos/data --storage-opt dm.metadatadev=/dev/centos/metadata
--storage-driver=devicemapper --storage-opt=dm.thinpooldev=/dev/mapper/docker-thinpool --storage-opt dm.use_deferred_removal=true
```
11. 清除之前的数据`rm -rf /var/lib/docker/*`
12. 重启docker服务



### ISCSI存储



术语：

- **iSCSI Initiator**: iSCSI initiators are clients that authenticate to an iSCSI target and get the authorization of block level storage access. Clients can have multiple iSCSI devices access the initiator.
- **iSCSI Target**: An iSCSI target is a server that provides storage to an iSCSI Initiator. You can create a LUN in a target and provide block storage to the iSCSI initiator.
- **LUN (Logical Unit Number)**: A LUN is a SCSI concept that allows us to divide a large number of the storage into a sizable chunk. A LUN is a logical representation of a physical disk. Storage which has been assigned to the iSCSI initiator will be the LUN.
- **IQN (iSCSI qualified name)**: An IQN is a unique name that is assigned to the iSCSI target and iSCSI initiator to identify each other.
- **Portal**: The iSCSI portal is a network portal within the iSCSI network where the iSCSI network initiates. iSCSI works over TCP/IP, so the portal can be identified by IP address. There can be one or more Portal.
- **ACL**: An access control list will allow the iSCSI initiator to connect to an iSCSI target. The ACL will restrict access for the iSCSI target so unauthorized initiators cannot connect

获取iscsi targets的NAA

```bash
[root@xxx]# /lib/udev/scsi_id --whitelisted --page=0x83 ip-10.125.31.41\:3260-iscsi-iqn.2000-05.com.3pardata\:20210002ac012e3b-lun-0
360002ac0000000000000046200012e3b
[root@nw-merge-150 by-path]# /lib/udev/scsi_id --whitelisted --page=0x83 ip-10.125.31.41\:3260-iscsi-iqn.2000-05.com.3pardata\:20210002ac012e3b-lun-1
360002ac0000000000000046100012e3b

360002ac0000000000000046100012e3b
|->                                 indicates a NAA identifier (3)
 |->                                indicates the IEEE Registered extended format (6)
  |____|->                          24-bit vendor ID (00:02:ac)
        |_______|->                 9 digits are the vendor specific id (000000000)
                 |______________|-> remaining 16 digits are the specific NAA id (0000 0461 0001 2e3b)
```



#### 使用iscsiadm客户端

关键概念：
- node record
- target portal
- target
- session
- lun

常用操作：

```bash
# manual示例：发现targets
iscsiadm --mode discoverydb --type sendtargets --portal 192.168.1.10 --discover
# manual示例：登录target
iscsiadm --mode node --targetname iqn.2001-05.com.doe:test --portal 192.168.1.1:3260 --login
# manual示例：登出target
iscsiadm --mode node --targetname iqn.2001-05.com.doe:test --portal 192.168.1.1:3260 --logout
# manual示例：列出node records
iscsiadm --mode node
# 删除node record
iscsiadm --mode node --op delete --portal 10.125.30.178
# manual示例：列出node record详细信息
iscsiadm --mode node --targetname iqn.2001-05.com.doe:test --portal 192.168.1.1:3260

# 查看当前会话
iscsiadm --mode session
# 重新扫描id为N的会话
iscsiadm --mode session --sid=N --rescan
# 查看会话详细信息
iscsiadm --mode session --sid=N --print 3

# 发现存储
iscsiadm --mode discovery --type sendtargets --portal x.x.x.x
# 登录和attach存储
iscsiadm --mode node --login
# 重新扫描
iscsiadm --mode session --rescan

iscsiadm -m iface -o show
iscsiadm -m iface -I default -o show
```

Kubernetes里iscsi存储插件代码中使用方法：

```bash
# AttachDisk
# build discoverydb and discover iscsi target
iscsiadm -m discoverydb -t sendtargets -p targetPortal -I iface -o new
# discover
iscsiadm -m discoverydb -t sendtargets -p targetPortal -I iface --discover
    # 当 discover 失败后 delete discoverydb record
    iscsiadm -m discoverydb -t sendtargets -p targetPortal -I iface -o delete
    # 例子
    iscsiadm -m discoverydb -p 10.125.30.178 -o delete
# login to iscsi target
iscsiadm -m node -p targetPortal -T iqn -I iface --login
    # 当 login to iscsi target 失败后 delete the node record from database
    iscsiadm -m node -p targetPortal -T iqn -I iface -o delete
    # 例子
    iscsiadm -m node -p 10.125.30.178 -o delete
# 当 node 错误或重启, 显示的设置 manual login so it doesn't hang on boot
iscsiadm -m node -p targetPortal -T iqn -o update -n node.startup -v manual
```



#### iscsi存储典型操作流程

1. 在存储服务器上新建存储卷
存储服务器配置顺序为：创建pool -> 创建块设备 -> 创建iSCSI的Target -> 设置IQN认证（紧接后面的第2步）

2. 将集群中各服务器加入该新建的存储卷中
注意，服务器的“发起程序节点名称”在`/etc/iscsi/initiatorname.iscsi`中获取

3. 在集群的各节点中执行存储卷发现和添加操作
```bash
iscsiadm -m discovery -t sendtargets -p 172.25.20.20    # 发现操作，-p后为存储portal地址
iscsiadm -m node -l   # 添加操作
```

4. 格式化存储卷
在`/dev/disk/by-path`中查看添加的网络存储卷
使用`mkfs.ext4`将上述存储卷格式化



#### targetcli设置iscsi本地调试环境

targetcli，administration shell for storage targets，可用于设置ISCSI的本地调试环境，进入`targetcli`后，执行如下命令：

```bash
cd /backstores/fileio
create storage1 /var/lib/iscsi_disks/storage1.img 1G
cd /iscsi
create iqn.2019-07.com.abc.ctt:storage1
cd /iscsi/iqn.2019-07.com.abc.ctt:storage1/tpg1/luns
create /backstores/fileio/storage1
cd /iscsi/iqn.2019-07.com.abc.ctt:storage1/tpg1/acls
create iqn.1994-05.com.redhat:df33382e31
create iqn.1994-05.com.redhat:eab9a033b8e6
create iqn.1994-05.com.redhat:fa6cc387d391
```





### FC存储

添加（再次添加）共享存储

```bash
echo "1" > /sys/class/fc_host/host1/issue_lip
```





### 存储多路径

常见操作

```bash
multipath -l
multipath -F
multipathd
```





## File system



### 内存文件系统

ETCD IO性能不足的银弹。

几个概念的对比：

* ramdisk是一个块设备，需要`mkfs`后才能使用。
* ramfs是 TODO
* tmpfs是一个文件系统，可直接挂载使用。

tmpfs有如下特点：
- 临时性，数据存在内存中，掉电后丢失。
- 读写性能卓越，远胜于磁盘和SSD（即使使用了swap）。
- 动态收缩，系统自动调整tmpfs下文件数据占用的内存。

如何使用tmpfs：
1. 创建目录 `mkdir /NODE1.etcd.tmpfs`
2. 将目录加载到内存设备中 `mount -ttmpfs -o size=5G,mode=0755 tmpfs /NODE1.etcd.tmpfs`
3. 【可选】动态调整文件系统大小 `mount -o remount,size=100M /NODE1.etcd.tmpfs`
4. 【警告】销毁内存文件系统 `umount /NODE1.etcd.tmpfs`
5. 系统启动时自动初始化tmpfs，在 `/etc/fstab` 中追加 `tmpfs /NODE1.etcd.tmpfs tmpfs size=100M,mode=0755 0 0`
6. 给ETCD的配置追加 ` --data-dir=/${ETCD_NAME}.etcd.tmpfs`

### xfs文件系统

将取代Ext4。



### samba

典型配置：
```bash
[root@workstation ~]# cat /etc/samba/smb.conf
[root]
   comment = root public dir
   path = /root
   browseable = yes
   read only =no
   guest ok =yes
```
还需要使用smbpasswd添加用户，才能登录。
```bash
smbpasswd -a root
```

在CentOS，若samba无法正常访问，需开启iptables规则，在 `/etc/sysconfig/iptables` 尾部、COMMIT前追加：
```bash
-A OS_FIREWALL_ALLOW -p tcp -m state --state NEW -m tcp --dport 445 -j ACCEPT
-A OS_FIREWALL_ALLOW -p udp -m state --state NEW -m udp --dport 445 -j ACCEPT
-A OS_FIREWALL_ALLOW -p udp -m state --state NEW -m udp --dport 137 -j ACCEPT
-A OS_FIREWALL_ALLOW -p udp -m state --state NEW -m udp --dport 138 -j ACCEPT
-A OS_FIREWALL_ALLOW -p tcp -m state --state NEW -m tcp --dport 139 -j ACCEPT
-A OS_FIREWALL_ALLOW -p udp -m state --state NEW -m udp --dport 3260 -j ACCEPT
-A OS_FIREWALL_ALLOW -p tcp -m state --state NEW -m tcp --dport 3260 -j ACCEPT
```
并重启iptables服务：
```bash
systemctl restart iptables
```

如果还是有问题，可尝试关闭`firewalld`服务。
```bash
systemctl stop firewalld
systemctl disable firewalld
```



### NFS

#### 搭建NFS测试环境

~~~bash
mkdir -p /exports/pv0001
yum install nfs-utils rpcbind -y
chown nfsnobody:nfsnobody /exports/ -R
ls -lZ /exports/pv0001/ -d
id nfsnobody
echo "/exports/pv0001 *(rw,sync,all_squash)" >> /etc/exports
systemctl start rpcbind
exportfs -r                 # 加载共享目录配置
exportfs -a                 # 加载共享目录配置
showmount -e                # 查看当前可用的共享目录
systemctl start nfs-server
sestatus
setenforce 0
sestatus
mount 10.125.30.252:/exports/pv0001 /mnt
touch /mnt/test
ls /mnt/
cd ~
umount /mnt
ls /exports/pv0001/
~~~

如果其它节点需要访问nfs服务，还需开放nfs访问端口
~~~
iptables -A IN_public_allow -p tcp --dport 2049 -j ACCEPT
iptables -A IN_public_allow -p tcp --dport 111 -j ACCEPT
iptables -A IN_public_allow -p tcp --dport 20048 -j ACCEPT
~~~


#### nfs问题定位手段

```bash
TODO
```



### webdav

对HTTP/1.1的扩展，支持`COPY`、`LOCK`、`MKCOL`、`MOVE`、`PROPFIND`、`PROPPATCH`和`UNLOCK`。

## Operation & Management

### 用户管理

```bash
groupadd                # 创建新的组
useradd -U zy           # 创建新的用户
passwd zy               # 创建（修改）用户密码
su - zy                 # 切换用户，推荐带上'--login'（缩写'-'），以确保像是一次真正的login
su [-] nova
usermod -s /bin/bash nova
```



### 系统资源限制

通过`/proc/<pid>/limits`查看进程（线程）的资源限制。

#### limits.conf资源限制

路径为`/etc/security/limits.conf`，详见`man limits.conf`。
增大open file限制

```bash
*          soft    nofile     204800
*          hard    nofile     204800
```
增大进程（线程）数限制
```bash
*          soft    nproc      59742
*          hard    nproc      59742
```
注意，`/etc/security/limits.d/20-nproc.conf`会覆盖 `/etc/security/limits.conf`中相同配置项的值，启机时读取顺序是先limits.conf再是`limits.d/*`下文件。

#### systemd资源限制

详见 `man systemd-system.conf`
涉及文件 `/etc/systemd/system.conf` 和 `/etc/systemd/user.conf`

```bash
DefaultLimitCORE=infinity
DefaultLimitNOFILE=102400
DefaultLimitNPROC=102400
```



### openssl和证书

常用命令

~~~bash
# 读取x509证书的信息
openssl x509 -in xxx.crt -text -noout
# 证书有效期起始时间
openssl x509 -in ${cert} -noout -dates | grep notBefore | awk -F"=" '{print $2}'
openssl x509 -enddate -noout -in file.pem
# 证书有效期截止时间
openssl x509 -in ${cert} -noout -dates | grep notAfter | awk -F"=" '{print $2}'
# certificate signing request (csr)
openssl req -new -out server.csr -config server.conf

# print csr
openssl req -in server.csr -noout -text

# sign a certificate
openssl x509 \
        -req \
        -days 3650 \
        -in server.csr \
        -CA ca.crt \
        -CAkey ca.key \
        -CAcreateserial \
        -out server.crt \
        -extensions harbor_extensions \
        -extfile ext.cnf

# print singed certificate
openssl x509 -in server.crt -noout -text

# 检查认证链（certificate chain）是否有效，设置SSL_CERT_DIR为dummy以防止使用系统安装的默认证书
SSL_CERT_DIR=/dummy SSL_CERT_FILE=/dummy openssl verify -CAfile ca.crt server.crt
SSL_CERT_DIR=/dummy SSL_CERT_FILE=/dummy openssl verify -CAfile ca.crt -untrusted server.crt
~~~

#### 生成根证书

```bash
openssl genrsa -des3 -out cacerts.key 2048
openssl req -x509 -new -nodes -key cacerts.key -sha256 -days 3650 -out cacerts.pem
```

#### 签发自签名证书

使用上述生成的根证书，签发自签名证书：

```bash
# 生成私有密钥
openssl genrsa -out key.pem 2048
# 生成csr
openssl req -new -key key.pem -out csr.epm
# TODO
```

#### 极简命令操作

```bash
# Generate the CA cert and private key
openssl req -nodes -new -x509 -keyout ca.key -out ca.crt -subj "/CN=Admission Controller Webhook Demo CA" -days 3650
# Generate the private key for the webhook server
openssl genrsa -out webhook-server-tls.key 2048
# Generate a Certificate Signing Request (CSR) for the private key, and sign it with the private key of the CA.
openssl req -new -key webhook-server-tls.key -subj "/CN=webhook-server.webhook-demo.svc" \
    | openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial -out webhook-server-tls.crt -days 3650
```


#### 自动化操作

```bash
# Country Name
CN="\r"
# State or Province Name
STATE="\r"
# cality Name
LN="\r"
# Organization Name
ON="\r"
# Organizational Unit Name
OUN="\r"
# Email Address
EA="\r"
# default null
DEFAULTNULL="\r"
# An optional company name
COMPANY="\r"
#
HOSTNAME='server.domain'
PASSWD='123456'

# 生成私有CA的证书ca.crt和秘钥ca.key
expect<<-EOF
set timeout 20
spawn openssl req -newkey rsa:4096 -nodes -sha256 -keyout ca.key -x509 -days 3650 -out ca.crt
expect "Country Name"
send ${CN}
expect "State or Province Name"
send ${STATE}
expect "Locality Name"
send ${LN}
expect "Organization Name"
send ${ON}
expect "Organizational Unit Name"
send ${OUN}
expect "Common Name"
send "${DEFAULTNULL}\r"
expect "Email Address"
send ${EA}
expect eof
EOF

# 生成key和csr，以用于签发证书
expect<<-EOF
set timeout 20
spawn openssl req -newkey rsa:4096 -nodes -sha256 -keyout server.key -out server.csr
expect "Country Name"
send ${CN}
expect "State or Province Name"
send ${STATE}
expect "Locality Name"
send ${LN}
expect "Organization Name"
send ${ON}
expect "Organizational Unit Name"
send ${OUN}
expect "Common Name"
send "${HOSTNAME}\r"
expect "Email Address"
send ${EA}
expect "A challenge password"
send "${PASSWD}\r"
expect "An optional company name"
send "${COMPANY}\r"
expect "eof"
EOF

cat > ext.cnf << EOF
[ extensions ]
basicConstraints=CA:FALSE
subjectAltName=@subject_alt_names
subjectKeyIdentifier=hash
keyUsage=nonRepudiation,digitalSignature,keyEncipherment

[ subject_alt_names ]
DNS.1 = ${HOSTNAME}
IP.1 = 1.2.3.4
EOF

openssl x509 -req -days 3650 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial  -extfile ext.cnf  -out server.crt

```



#### 根证书缺失导致TLS通信失败

以docker服务访问为例，当遇到如下问题时，可考虑由缺乏签发Server证书的根证书（CA Cert）导致：

```
Error response from daemon: Get https://registry-1.docker.io/v2/: x509: certificate signed by unknown authority
```

要解决上述问题，需添加CA根证书：

```bash
# 将知名的CA根证书拷贝到 /etc/pki/ca-trust/source/anchors 路径下，执行如下更新命令
update-ca-trust extract
# 重启docker服务
systemctl restart docker
```

同时，还存在如下**临时方案**：

```bash
openssl s_client -connect docker-registry:443 -showcerts </dev/null 2>/dev/null | openssl x509 -outform PEM | tee /etc/pki/ca-trust/source/anchors/docker-registry.crt
update-ca-trust
```







### 远程安全终端openssh

#### 服务端sshd

必须带全路径才能启动sshd，例如`/usr/bin/sshd`。

若启动时提示
* /etc/ssh/ssh_host_dsa_key
* /etc/ssh/ssh_host_ecdsa_key
* /etc/ssh/ssh_host_ed25519_key
* /etc/ssh/ssh_host_rsa_key

找不到，则需要使用`ssh-keygen`命令，生成上述key文件

```bash
ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key
```

常用命令：

```bash
sshd -T | grep kex    # 获取sshd服务端支持的加密算法
```



#### 客户端ssh

常用命令：

```bash
ssh root@172.25.19.117 ps -ef | grep kube-controller | grep -v grep     # 远程到某节点执行命令，然后直接在本地返回执行结果
ssh -o StrictHostKeyChecking=no op-s1 ls        # 初次连接，跳过恼人的主机host fingerprint检查
ssh -Q kex    # 获取ssh客户端支持的加密算法
```



#### ssh免密登录

服务端（被连接者）中`~/.ssh/authorized_keys`加入客户端（连接发起者）的公钥。
注意，客户端的`~/.ssh/`中需要有与该公钥对应的私钥。

如何定位免密登录问题：

```bash
ssh -v master           # 查看客户端操作详细信息
journalctl -u sshd      # 查看服务端日志，必要情况下可增加'-d'选项查看更详细的debug信息
```



### 使用gost配置隧道

项目地址`https://github.com/ginuerzh/gost`

```bash
# Windows跳板机上创建proxy.bat批处理文件，其执行如下内容
gost -D -L=http://:8080/ -F=http://<代理服务器地址>:<代理服务器端口>/
```



### Alpine

#### 使用镜像源

```bash
echo "http://mirrors.aliyun.com/alpine/v3.6/main/" > /etc/apk/repositories && \
echo "http://mirrors.aliyun.com/alpine/v3.6/community" >> /etc/apk/repositories
```

#### 下载软件包及其依赖到本地

```bash
apk fetch -R python
```

#### 安装本地软件包

```bash
apk add --allow-untrusted /gdbm-1.12-r0.apk
```



### Debian

```bash
# 设置仓库
update-command-not-found
deb http://1.2.3.4/debian/ jessie main contrib non-free
apt-get update

# 安装单个deb包
dpkg -i path_to_deb_package.deb

# 修理安装deb包引起的依赖问题
apt-get -f install

# apt下载的deb包的缓存
/var/cache/apt/archive
```

#### 添加仓库

依赖包： software-properties-common 和 python-software-properties

```bash
add-apt-repository ppa:nhandler/ppa
```

### CentOS

#### 常用操作

删除老的、不用的内核Kernel

```bash
rpm -q kernel # 查询有哪些kernel
package-cleanup --oldkernels --count=2   # 删除老的不用的kernel，并保留最近2个kernel
```

查看系统可用内核的索引值

```bash
awk -F\' '$1=="menuentry " {print i++ " : " $2}' /etc/grub2.cfg
```

修改默认引导的内核

```bash
grub2-editenv list
grub2-set-default 1
grub2-editenv list
```

升级内核前若替换了reboot和shutdown命令，升级内核后节点将无法reboot或shutdown

```
升级内核会重新生成initramfs.img，该镜像负责最后重启关机工作。
升级前若替换了reboot和shutdown命令，则替换后的命令会被打进新的initramfs.img，最终影响重启关机操作。
解决办法是升级内核前将reboot和shutdown命令替换回系统初始状态，待升级后再恢复。
```

新增内核模块

```bash
# 降低新编译内核模块的大小
strip --strip-debug drbd.ko
# 复制新增内核模块到指定位置
cp drbd.ko /lib/modules/${uname -r}/extra/
# 更新内核模块依赖信息
depmod -a
```

查看CentOS版本信息

```bash
hostnamectl
rpm --query centos-release
cat /etc/*-release
```

安装和运行GNOME桌面

```bash
yum -y groups install "GNOME Desktop"
startx
```

默认启动图形化界面

```bash
systemctl set-default graphical.target
```

使用GNOME Shell

```bash
echo "exec gnome-session" >> ~/.xinitrc
startx
```



#### 关闭coredump

**普通进程**

参考[文档](https://linux-audit.com/understand-and-configure-core-dumps-work-on-linux/)

1. 配置文件`/etc/security/limits.conf`中增加：
~~~
* hard core 0
~~~
2. 配置文件`/etc/sysctl.conf`中增加：
~~~
fs.suid_dumpable = 0
~~~
并执行`sysctl -p`是配置立即生效。
3. 配置文件`/etc/profile`中增加：
~~~
ulimit -S -c 0 > /dev/null 2>&1
~~~

上述操作，在用户重新登录后生效。

**systemd服务**

*验证无效，即使重启节点。*

修改配置文件`/etc/systemd/coredump.conf`：
~~~
[Coredump]

Storage=none
ProcessSizeMax=0
~~~



### 主机资源监控

#### 常用命令

```bash
# 排查load average过高的可疑线程
# milk-cdn服务产生很多Dl状态(不可中断线程)的线程，导致load average很高，重启服务后恢复正常。目前在持续观察这种情况如何产生。
ps -eTo stat,pid,tid,ppid,comm --no-header | sed -e 's/^ \*//' | perl -nE 'chomp;say if (m!^S*[RD]+\S*!)'
top                 #监控进程/线程状态    ->f->选择关注项
ps                  #查看进程/线程
ps -o ppid= 19312   #查找19312的父进程，注意 ppid= 和 19312 间的空格
pstree -l -a -A pid #查看进程树
iftop               #监控网络
top -H -p pid
top -b -n 1             # batch模式，输出1次
slabtop             #监控内存SLAB使用情况
cat /proc/meminfo
    MemTotal:       98707036 kB
    MemFree:        60587804 kB
    MemAvailable:   76521792 kB
    Buffers:          199108 kB
    Cached:         18710356 kB
    SwapCached:       813128 kB
    Active:         20548488 kB
    Inactive:       14160184 kB
    Active(anon):   15412388 kB
    Inactive(anon):  3855104 kB
    Active(file):    5136100 kB
    Inactive(file): 10305080 kB
    Unevictable:        8624 kB
    Mlocked:            8624 kB
    SwapTotal:       4194300 kB
    SwapFree:        2831864 kB
    Dirty:               232 kB
    Writeback:             0 kB
    AnonPages:      15291684 kB
    Mapped:           430144 kB
    Shmem:           3464324 kB
    Slab:            1893012 kB
    SReclaimable:     999628 kB
    SUnreclaim:       893384 kB
    KernelStack:      104736 kB
    PageTables:        68900 kB
    NFS_Unstable:          0 kB
    Bounce:                0 kB
    WritebackTmp:          0 kB
    CommitLimit:    53547816 kB
    Committed_AS:   45280032 kB
    VmallocTotal:   34359738367 kB
    VmallocUsed:      707420 kB
    VmallocChunk:   34291471360 kB
    HardwareCorrupted:     0 kB
    AnonHugePages:  11507712 kB
    HugePages_Total:       0
    HugePages_Free:        0
    HugePages_Rsvd:        0
    HugePages_Surp:        0
    Hugepagesize:       2048 kB
    DirectMap4k:      170240 kB
    DirectMap2M:     5994496 kB
    DirectMap1G:    96468992 kB
ifstat
iostat -x -k -d 1   #查看I/O详细信息
iostat -x           #查看系统各个磁盘的读写性能，关注await和iowait的CPU占比
time python -c "2**1000000000"  # CPU性能
iotop               #监控磁盘IO操作
mpstat              # 查看资源使用率的【利器】，说明详见man mpstat
mpstat.steal        # 检查vm的cpu资源是否被hypervisor挪用
pidstat
pidstat -p pid -r 1 #
vmstat 3 100        #查看swap in/out
vmstat -m           #查看slab信息   vm.min_slab_ratio 检查slab与vm的比例
vmstat -s           #显示事件计数器和内存状态
cat /proc/vmstat | grep 'pgpg\|pswp'     #查看page交换in/out的统计值
ps -eo min_flt,maj_flt,cmd,pid    #查看 page faults 统计信息，有Minor、Major、Invalid三种 page faults类型
slabtop -s c        #查看slabinfo信息
pmstat              #查看系统全局性能  high-level system performance overview
sar -r 3            #查看内存使用情况（不包括swap）来自package: pcp-import-sar2pcp
sar -u 3            #查看CPU消耗情况
sar -q 3            #查看CPU load
sar -n SOCK         #查看网络流量
watch more /proc/net/dev    #定位丢包情况
cat /proc/net/snmp  #查看和分析240秒内网络包量、流量、错包、丢包，重传率时RetransSegs/OutSegs
dig @127.0.0.1 -4 masternode  #查看域名解析地址，其中指定server为127.0.0.1，且仅查询A记录（ipv4）
iostat -x 1         # 查看cpu和硬盘io信息
dstat               # 查看CPU、MEM、硬盘io信息
dstat --aio --io --disk --tcp --top-io-adv --top-bio-adv
dstat -m --top-mem  # 查看内存占用最多者
mpstat -P ALL 1     # 每个CPU核的使用率
dmesg -H            # 查看kernel信息
perf
virt-what           # 判断是否虚拟机（Guest、VM）运行
ss state ESTABLISHED    #查看TCP已连接数
ss -s
ss -aonp            # 查看套接字 socket 连接信息，基本等同于 netstat -ptn
netstat -aonp
lsblk
ethtool				# 查看以太接口信息
du -d 1 -h
du -sh --exclude='lib/*' # 统计时排出lib目录下所有内容
```



#### lsof查看打开文件

```bash
# 统计打开文件数
lsof -n | awk '{print $2}' | grep -v PID | sort | uniq -c | sort -n

lsof /etc/passwd            #哪个进程打开了/etc/passwd文件
lsof `which httpd`          #哪个进程在使用Apache可执行文件
lsof -i:2375
lsof -p pid                 #显示进程pid打开的文件，这种方式不会重复统计进程中线程的fd数量
for i in $(ps -ef | grep shim | grep -v grep | grep -v "\-\-shim" | awk '{print $2}'); do echo $i $(lsof -p $i | wc -l); done

# 统计、查看未关闭文件句柄的进程
lsof 2>/dev/null | grep -i deleted | awk '{print $2}' | sort -n | uniq -c | sort -nr
```



#### fuser查找资源使用

当挂载点无法umount、提示“device is busy”时，能够使用fuser查找到谁在使用这个资源。

```bash
# 查找哪些用户和进程在使用该设备
fuser -vam /dev/sdf
```

同时也能查看谁在占用端口：

```bash
# 查找哪些用户和程序使用tcp的80端口
fuser -v -n tcp 80
```



#### netstat查看网络资源

常用操作：

```bash
netstat -anp    #查看所有连接及其pid
```





### 性能调优和问题定位

#### CPU性能

##### 设置或提升CPU运行频率
```bash
# 查询CPU额定主频
cat /proc/cpuinfo
# 最后参数是额定主频
cpupower frequency-set -f 2.5GHz
# 卸载pcc_cpufreq内核模块
modprobe -r pcc_cpufreq
```
##### 解决pcc和acpi的bug导致的CPU降频问题

```bash
modprobe -r pcc_cpufreq
modprobe -r acpi_cpufreq
echo "blacklist pcc-cpufreq" >> /etc/modprobe.d/cpufreq.conf
echo "blacklist acpi-cpufreq" >> /etc/modprobe.d/cpufreq.conf
```



#### 网络性能

使用`iperf`测试网络性能：

```bash
iperf -s                 # 服务端执行
iperf -c <serverIP>      # 客户端执行
```



#### IO性能

##### ionice修改io优先级

使用`ionice`提升/限制磁盘IO性能：

```bash
# 提升etcd3的磁盘IO操作优先级
ionice -c2 -n0 -p $(pgrep -w etcd3)
```

在脚本开头增加
```bash
ionice -c3 -p$$
```
此后该脚本所有操作的io优先级，均被修改为idle class。



##### fio性能测试

用于测试硬盘性能，准备2GB文件`/tmp/test`。

```bash
# 顺序读性能
fio --filename=/tmp/test -iodepth=64 -ioengine=libaio --direct=1 --rw=read --bs=1m --size=2g --numjobs=4 --runtime=10 --group_reporting --name=test-read-linear

# 顺序写性能
fio --filename=/tmp/test -iodepth=64 -ioengine=libaio --direct=1 --rw=write --bs=1m --size=2g --numjobs=4 --runtime=20 --group_reporting --name=test-write-linear

# 随机读性能
fio --filename=/tmp/test -iodepth=64 -ioengine=libaio --direct=1 --rw=randread --bs=4k --size=2g --numjobs=64 --runtime=20 --group_reporting --name=test-rand-read

# 随机写性能
fio --filename=/tmp/test -iodepth=64 -ioengine=libaio --direct=1 --rw=randwrite --bs=4k --size=2g --numjobs=64 --runtime=20 --group_reporting --name=test-rand-write

# 针对device的压力测试
# 注意，其中-filename指定的设备会被随机读写，请确保上面没有关键数据
fio -filename=/dev/sda1 -direct=1 -iodepth 1 -thread -rw=randrw -rwmixread=70 -ioengine=psync -bsrange=512-10240 -numjobs=1 --rate 1M -runtime=6000 -time_based -group_reporting -name=randrw_70read_4k_local

# 另一个测试命令实例
fio --filename=/tmp/1G -iodepth=64 -ioengine=libaio --direct=1 --rw=randwrite --bs=4k --size=1g --numjobs=64 --runtime=10 --group_reporting --name=test
```





##### iozone

TODO



### 文件系统修复

常用操作：

```bash
blkid                                   # 获取所有分区的uuid信息，包括文件系统类型
fsck -n /dev/dm-0

tune2fs -l /dev/dm-0                    # 查看文件系统健康相关信息
tune2fs -l /dev/dm-0 | grep Last\ c     # 查看最近一次文件系统检查时间
tune2fs -l /dev/dm-0 | grep Mount       # 查看文件系统挂载了多少次
tune2fs -l /dev/dm-0 | grep Max         # 强制检查的最大挂载次数，当为-1是表示强制检查被关闭了
tune2fs -c 1 /dev/dm-0                  # 设置强制检查的最大挂载次数为1，若fstab中第6列设置为1，则每次挂载都会检查dm-0上的文件系统

# 在待强制检查的文件系统根目录下，创建空文件forcefsck，触发强制检查，检查后会自动删除该文件
touch forcefsck

e2fsck -n /dev/sde # 先了解下
e2fsck -y /dev/sde # 然后修复
```





### 软件包管理

#### rpm

rpm是一种包格式，也是其管理工具的名称，来自`package rpmdevtools`

```bash
rpminfo
rpmls
rpm -ivh package.rpm
rpm -q kernel
```



#### yum

```bash
yum install man-pages   # 安装系统帮助文档manual
yum install man-db      # 安装系统帮助文档manual
yum localinstall *.rpm
yum updateinfo
yum reinstall --downloadonly --downloaddir=./ <PackageName>-<Version>.<Arch>    # 下载package指定版本的rpm包至本地
yumdownloader --resolve systemd-219-57.el7_5.1.x86_64                           # 下载package及其依赖的rpm包至本地
yumdownloader   # 属于yum-utils package
yumdownloader --source <package-name> # 下载该package的源码包，可以从中获取SPEC文件，再本地编译package。
yum history # 查看操作历史
createrepo /opt/repo/openshift  # 创建yum repo
yum deplist httpd-tools         # 获取httpd-tools依赖的packages
yum resolvedep httpd-tools      # 获取谁依赖httpd-tools
```





### 域名解析

#### nslookup

属于bind-utils包。

kube-dns的健康检查healthz容器使用如下命令对kube-dns进行检查

```bash
nslookup kubernetes.default.svc.local 127.0.0.1
```

曾遇到问题环境，由于节点在`etc/resolv.conf`中配置了IPv6的nameserver且其为第一个nameserver，healthz容器执行nslookup时，虽然指定server为127.0.0.1，但仍然优先选取这个IPv6的nameserver，导致解析kubernetes.default.svc.local失败。
作为对比，当节点中`/etc/resolv.conf`配置了IPv4的nameserver且其为第一个nameserver时，不会出现上述问题。

### 时钟同步

#### ntp

实现集群各节点的时间同步。

##### 优化NTP
配置优化`/etc/ntp.conf`：

1. 从节点取消以自身为时钟源进行同步。从节点必须且只能与主节点同步，否则同步无意义。即便集群时间与RTC不一致，至少不影响集群整体正常工作。集群内部时钟同步为第一优先级。
2. 增加参数“maxpoll 6”。ntpd默认同步间隔最短64秒（minpoll 6），最长1024秒（maxpoll 10），最长同步时长改为64秒后强制每64秒同步一次，避免某些机器时钟源不稳定，在1024秒同步间隔内出现较大偏差。
3. 主节点配置有多个外部时钟源时，应使用prefer选项设置主时钟源。

服务优化`/usr/lib/systemd/system/ntpd.service`：
1. ntpd取消-g选项，即ntpd在发现时间相差超过1000秒时退出。
2. 重启策略改为always。
3. 增加ntpd服务启动前执行命令 ntpd –qg，即启动前强制与时钟源同步一次，即使时间差超过1000秒。

主节点`/etc/ntp.conf`示例：
~~~bash
driftfile /var/lib/ntp/drift
restrict default nomodify notrap nopeer noquery
restrict 127.0.0.1
restrict ::1

server external1 prefer maxpoll 6  #存在多个外部时钟源时使用prefer设定优先级，其他源为同级
server external2 maxpoll 6
server 127.127.1.0 iburst maxpoll 6
fudge 127.127.1.0 stratum 10

includefile /etc/ntp/crypto/pw
keys /etc/ntp/keys
disable monitor
~~~

从节点`/etc/ntp.conf`示例：
~~~bash
restrict default nomodify notrap nopeer noquery
restrict 127.0.0.1
restrict ::1

server 10.125.30.147 iburst maxpoll 6  # 注意：不含主节点外其他时钟源

includefile /etc/ntp/crypto/pw
keys /etc/ntp/keys
disable monitor
~~~

ntpd服务配置`/usr/lib/systemd/system/ntpd.service`示例：
~~~bash
[Unit]
Description=Network Time Service
After=syslog.target ntpdate.service sntp.service

[Service]
Type=forking
EnvironmentFile=-/etc/sysconfig/ntpd
ExecStartPre=/usr/sbin/ntpd -qg  #启动前强制同步
ExecStart=/usr/sbin/ntpd -u ntp:ntp  #取消-g选项
PrivateTmp=true
Restart=always  #总是重启
RestartSec=10

[Install]
WantedBy=multi-user.target
~~~

##### 手动执行集群内时间同步的操作

使用ntpdate命令强制同步时间：

~~~
systemctl stop ntpd
ntpdate <master-ip>
systemctl start ntpd
~~~

##### ntp服务自我保护
ntp默认有1000秒的保护时间限制，当节点间时间差超过1000秒，ntpd服务将不会同步时间。
在保护时间限制内，采用渐进的同步方式，即不是一步到位的fix时间差，而是逐渐弥合差异。

##### 常用命令和工具

ntpstat

```bash
ntpstat
```

timedatectl

```bash
[root@zy-op-m ~]# timedatectl
      Local time: Mon 2018-12-03 14:32:22 CST
  Universal time: Mon 2018-12-03 06:32:22 UTC
        RTC time: Mon 2018-12-03 06:32:22
       Time zone: Asia/Shanghai (CST, +0800)
     NTP enabled: yes
NTP synchronized: yes
 RTC in local TZ: no
      DST active: n/a
[root@zy-op-m ~]# timedatectl set-ntp true
```
ntpq

~~~bash
ntpq -p   # 查看当前从谁那里同步时间
~~~



#### chronyd

对ntp的改良。



### 如何Debug程序和进程

#### pmap分析内存使用

```bash
pmap -x pid     # 查看详细信息
pmap -XX pid    # 查看kernel提供的所有信息
```

#### strace查看进程调用链

```bash
strace -f -e trace=access curl 'https://10.100.0.1/'
strace -fc -e trace=access curl -s 'https://10.100.0.1/' > /dev/null
# 找配置文件的奇技淫巧
strace -eopen pip 2>&1|grep pip.conf
```

#### pstack分析CPU异常高时堆栈信息

```bash
top                 #找到CPU占用率高的进程ID
top -c -H -p <pid>  #找到CPU占用率最高的线程ID
pstack <tid>        #查看该线程的调用栈
pstack是gstack的链接，gstack是脚本，属于gdb这个package。
```

#### ldd查看可执行文件依赖库

```bash
ldd
```

#### abrtd自动报告bug

abrtd是Redhat的Automatic bug reporting tool，相关的工具和命令包括：`abrt-auto-reporting`和`abrt-cli`。

#### scanelf获取运行时依赖（动态链接库）
```bash
scanelf --needed --nobanner --recursive /usr/local \
      | awk '{ gsub(/,/, "\nso:", $2); print "so:" $2 }' \
      | sort -u \
      | xargs -r apk info --installed \
      | sort -u
```



#### time查看执行时间

```bash
[zy@m1 ~]$ time sleep 1s

real    0m1.001s
user    0m0.001s
sys     0m0.000s
```



#### coredump分析

查看Core Dump文件保存路径

```bash
cat /proc/sys/kernel/core_pattern
```



### 文本、字节流编辑

```bash
sed '1d'   #跳过（删除）第一行
sed '$d'   #跳过（删除）最后一行
sed '1,17d' #删除第1到第17行
sed "s|{INITIAL_CLUSTER}|${INITIAL_CLUSTER}|g" os-param-rc.yaml    # 如果替换的字符串中有'/'，则sed的间隔附可替换为'|'
sed -i "/Listen 35357/a\ListenBacklog 4096" /etc/httpd/conf.d/wsgi-keystone.conf
sed -i "s/^Listen 80$/Listen 8080/g" /etc/httpd/conf/httpd.conf
sed -i "0,/#enabled = true/s//enabled = true/" /etc/keystone/keystone.conf
sed -i "1,/#transport_url=<None>/s/#transport_url=<None>/transport_url=rabbit:\/\/openstack:${RABBITMQ_PASS}@${RABBITMQSVC}/" /etc/neutron/neutron.conf
sed -i "s/#OPENSTACK_API_VERSIONS = {/\
OPENSTACK_API_VERSIONS = {\n\
    \"identity\": 3,\n\
    \"image\": 2,\n\
    \"volume\": 2,\n\
}\
/g" /etc/openstack-dashboard/local_settings
sed 's/[[:space:]]//g'  # 去掉字符串中的空格' '
sed -e 's/{[0-9]\+}/%s/g'  # 使用正则表达式
cat api_raw.txt | grep -v "PUT" | grep "GET /systemparameters?paramName=" | sed "s/.*paramName=//g" | awk '{print $1}' | sort -u
sort -u rancher-images.txt -o rancher-images.txt  # 将一个文件中的重复行去掉
find . -name "compcas*" | xargs sed "s/D1101/D1101-stub/g" -i
find /proc/*/fd -lname anon_inode:inotify | cut -d/ -f3 | xargs -I '{}' -- ps --no-headers -o '%p %U %c' -p '{}'
find /lib/systemd/system/sysinit.target.wants/ -name "systemd-tmpfiles-setup.service" -delete
cat 172.25.18.178-mongodbreq.log | sed "s/\./ /g" | awk '{print $1"."$2"."$3"."$4}' | sort -r | uniq -c >> 172.25.18.178-mongodbreq.digest
hehe=0101;hehe=$(echo $hehe | sed "s/^0*//g");echo $hehe
ps -e -o "pid,comm,rss" | grep docker | awk '{a+=$3}END{print a}'   # 统计docker相关的进程占用的内存总数
ps -e -o "pid,comm,rss" | grep -v PID | awk '{a+=$3}END{print a}'
ps -ef | awk '{print $NF, $(NF-1)}'
ip addr |grep $local_ip |awk '(NR == 1) {print $NF}'
grep -Eo "mysql-node[0-9]+" #仅返回匹配值
cut -d/ -f3  #  以'/'进行分隔，获取第3区域的内容
+------------------+----------+--------------+---------------------------------------+-------------------+
| File             | Position | Binlog_Do_DB | Binlog_Ignore_DB                      | Executed_Gtid_Set |
+------------------+----------+--------------+---------------------------------------+-------------------+
| mysql-bin.000930 |     1930 |              | information_schema,performance_schema |                   |
+------------------+----------+--------------+---------------------------------------+-------------------+
mysql -u${CLUSTER_USER} -e "show master status" |cat |sed -n "2p"|awk '{print "file="$1";pos="$2}'
cut -d '|' -f 5  #  以'|'为间隔，截取第5个成员
echo 'server1            | mysql-node1     |  3306 |          27 | Slave, Running' | cut -d '|' -f 5
docker ps | grep -v POD | awk '{print $NF}' | cut -d_ -f2-4
docker images | grep :9999/ | tr -s ' ' | cut -d ' ' -f1,2     # 使用tr和cut命令，替代awk
echo 1.24GBi | tr -d '[A-Z][a-z]'
echo ${routes} | tr ' ' '\n' | grep -c eth0    # 统计一样中某个单词的出现数量

```



### L2TP without IPsec配置

网络配置

```bash
使能: /proc/sys/net/ipv4/ip_forward
如果需要通过VPS访问互联网，还需开启源地址伪装: iptables -t nat -A POSTROUTING -j MASQUERADE
如果开启了防火墙，还必须开启 udp 1701 端口
```
安装xl2tpd

```bash
yum install xl2tpd
```
L2TP客户端配置

```bash
#cat /etc/xl2tpd/xl2tpd.conf
[global]
access control = no
debug avp = no
debug network = no
debug packet = no
debug state = no
debug tunnel = no

[lac tj-region]
lns = 1.2.3.4
name = user
require chap = yes
require pap = no
require authentication = yes
ppp debug = no
pppoptfile = /etc/ppp/options.xl2tpd
redial = yes
redial timeout = 5
autodial = yes

#cat /etc/ppp/options.xl2tpd
ipcp-accept-local
ipcp-accept-remote
refuse-eap
require-chap
noccp
noauth
mtu 1410
mru 1410
nodefaultroute
debug
connect-delay 5000
name user
password xxx
```

利用ppp的ip-up钩子脚本，自动配置接口路由。如果不存在则创建`/etc/ppp/ip-up`文件，并确保其具备可执行权限，ppp拨号成功并创建接口后会自动调用执行该脚本。/etc/ppp/ip-up中增加

```bash
# 其中$1是VPN接口，例如ppp0
/usr/sbin/route add -net 100.64.1.0 netmask 255.255.255.0 dev $1
```

最后，使能L2TP服务

    systemctl enable xl2tpd && systemctl start xl2tpd



### 日志

#### shell脚本使用logger输出日志

shell脚本记录日志统一使用 `logger` 命令，格式：
~~~bash
# -p 可以使用 user.info user.warning user.error
# -t 是模块名 最好直接使用脚本名称
logger -p user.info -t modname message
~~~
输出的日志可通过journalctl查看。

#### 使用journalctl查看日志

```bash
journalctl              # 查看CentOS上服务的log，包括Kubernetes/docker/flannel/etcd等服务都能通过该命令查看log
journalctl -xe          # 查看尾部的日志
journalctl --no-pager -u docker
journalctl -k           # 仅查看内核日志
journalctl --since="19:00:00" -u docker
journalctl --since="2018-02-21 19:00:00"
journalctl --vacuum-size=2G --vacuum-time=1week
journalctl -b -u docker # 自某次引导后的信息
```





### 其它技巧

curl常用命令

```bash
# 向静态文件服务器上传静态资源文件
curl -u 'user:password' -X PUT "url_to_file" -T path_to_file -v
```

查看系统开机时间

```bash
who -b
```

查看系统运行时间

```bash
who -r
```

某些容器中curl由于版本问题，不支持https

解决办法是更新curl及其依赖库`yum update -y nss curl libcurl`

安装并查看Linux内核文档

```bash
yum install kernel-doc
```
在路径`/usr/share/doc/kernel-doc-x.y.z`下可找到Documentation文件夹。

nl打印时显示行号

```bash
lsof | nl
```

使用bc做数值计算

```bash
echo "${curr_freq_M} / ${full_freq_G} / 10" | bc
```

后台Daemon方式执行命令和脚本

```bash
setsid xxx.sh >/dev/null 2>&1 < /dev/null &
# or
nohup ./*.sh  >/dev/null 2>&1 &
```
很多时候，由于异步执行，可能未执行setsid后面的命令就退出了，这时只需要在最后加上sleep延迟下就好。

忽略命令执行时的输出

```bash
curl http://192.168.11.131/cloud/login.xhtml 1>/dev/null 2>&1
```

使用`readlink`获取文件链接信息：

```bash
# 获取链接文件指向的文件
readlink -f /var/log/kubernetes/kube-proxy.INFO
```

hydra暴力破解密码

```bash
hydra -l root -P /root/2.txt 100.64.1.30 ssh
hydra -l root -P /root/pass.txt 100.64.1.30 mysql
```

uuidgen生成uuid

timeout为程序设置执行超时

```bash
# 给命令的执行加上一个期限
timeout 1s maxadmin list servers
```

硬盘检查

```bash
systemctl start smartd
systemctl status smartd
smartctl -i /dev/sda
smartctl -s on /dev/sda
smartctl -a /dev/sda

# 坏道检查
badblocks
```

使用grubby修改内核启动参数

```bash
grubby --args="user_namespace.enable=1" --update-kernel="$(grubby --default-kernel)"
```

使用`rsync`同步文件夹

```bash
TODO
```

使用linux-ftools

使用fincore

使用fadvise

使用losetup

使用find查找文件

```bash
find /var/log/kubernetes -type l  # 查找链接文件
find ${log_path} -mtime +14 -type f -name "*" -exec rm -rf {} \      #  查找并删除15天以上未修改的文件
find . -type f -exec doc2unix {} \; # 替换成unix风格
find . -type f ! -name "*.gz"
find ${volume_dir} -maxdepth 1 -mindepth 1 -type d
```



配置ls的颜色

```bash
/etc/DIR_COLORS
```

使用mktemp创建临时文件。

其它小点：

```bash
zip -r images images              # zip压缩
hexdump -C xxx.bin                # 二进制文件查看工具
realpath file                     # 获取file的绝对路径
stat -L /var/log/kubernetes/kube-proxy.INFO # 查看链接文件详细信息
echo $(($(cat /dev/urandom | od -A none -w2 | head -n 1) % 3500)) #  生成随机数
mount -o loop -t iso9660 /root/xxx.iso /root/isomount/
mtr # 比 traceroute 更好用的路由追踪工具
ps -ax --width 100000   # 通过ps查看进程的执行命令和参数时，若遇到被截断，可指定--width显示完整的命令和参数信息
date +"%Y-%m-%d %T"
date +"%F %T.%3N"
date --date='Mon Apr 2 00:21:03 2018' +'%s'    # date的格式化输入和格式化输出
date -d "10 day ago" +"%Y-%m-%d"               # 符合自然语言的输入和格式化输出
echo -e '\n1.2.3.4 hehe\n2.3.4.5 xixi\n' >> /etc/hosts
echo ${a%?}  # 无条件去掉最后一个字符
```



# Docker and Containers



## cgroup

cgroup的原生接口通过cgroupfs提供，类似于procfs和sysfs，是一种虚拟文件系统，用户可以通过文件操作实现cgroup的组织管理。

cgroup可以限制、记录、隔离进程组所使用的物理资源。

子进程创建之初，与其父进程处于同一个cgroup的控制组里。

cgroup实现本质上是给系统进程挂上hooks，当task运行过程中涉及到某类资源的使用时就会触发hook上附带的子系统进行检测。

主要作用包括：

- 资源限制：可以对进程组使用的资源总额进行限制（例如内存上限，一旦超过配额就触发OOM异常）
- 优先级分配：通过分配的CPU时间片数量及硬盘IO带宽大小，相当于控制进程运行的优先级
- 资源统计：统计系统的资源使用量，如CPU使用时长、内存用量等，非常适用于计费和监控
- 进程控制：对进程组执行挂起、恢复等操作

### cgroup子系统

| 类型       | 说明                                                         |
| ---------- | ------------------------------------------------------------ |
| cpuset     | 为cgroup中的task分配独立的cpu（针对多处理器系统）和内存      |
| cpu        | 控制task对cpu的使用                                          |
| cpuacct    | 自动生成cgroup中task对cpu资源使用情况的报告                  |
| memory     | 设定cgroup中task对内存使用量的限定，并且自动生成这些task对内存资源使用情况的报告 |
| blkio      | 为块设备设定输入/输出限制                                    |
| devices    | 开启或关闭cgroup中task对设备的访问                           |
| freezer    | 挂起或恢复cgroup中的task                                     |
| net_cls    | docker没有直接使用，其通过使用等级识别符（classid）标记网络数据包，从而允许Linux流量控制（TC）程序识别从具体cgroup中生成的数据包 |
| perf_event | 对cgroup中的task进行统一的性能测试                           |
| hugetlb    | TODO                                                         |

### 挂载cgroupfs

以cpuset子系统为例：

```bash
mount -t cgroup -o cpuset cpuset /sys/fs/cgroup/cpuset
```

### 常用操作

```bash
mount -t cgroup
lssubsys -m
ls -l /sys/fs/cgroup/
lscgroup
man cgconfig.conf
cgcreate
cgdelete
```



## namespaces

### 常用工具

#### lsns

`lsns`工具来自包`util-linux`，其常见使用如下：

```bash
lsns -t net
```



#### nsenter

```bash
nsenter --net=/proc/19714/ns/net ip addr
nsenter -t 19714 -u hostname
nsenter -t 19714 -m -u -i -n -p bash
nsenter -t 19714 -m -p bash
nsenter -t 12472 -m -p umount /var/lib/origin/openshift.local.volumes/pods/<uid>/volumes/ctriple.cn~drbd/r0002
nsenter -t 19714 -m -p ps -ef
nsenter -t ${pid} -m cat /sys/devices/virtual/net/eth0/iflink 2>/dev/null
nsenter -t 7429 -n cat /proc/net/route
```



#### unshare

使用不同的命名空间运行程序，详见`man 1 unshare`

>run program with some namespaces unshared from parent



## 容器安全

参考文档：

- [Overview Of Linux Kernel Security Features](https://www.linux.com/tutorials/overview-linux-kernel-security-features/)
- [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Pod Security Policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)

### Discretionary Access Control

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



### linux capabilities

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
        add: ["SYS_TIME"]
~~~

注意，在add和drop时，去掉了前缀`CAP_`。

### seccomp

Filter a process’s system calls. 相较linux capabilities，权限控制粒度更细。

以设置系统时间为例：

~~~bash
[root@zy-super-load ~]# strace date -s "15:22:00" 2>&1| grep -i time
...
clock_settime(CLOCK_REALTIME, {1575530520, 0}) = 0
...
~~~

其用到了系统调用`clock_settime`。

为Pod设置seccomp profile

~~~yaml
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
~~~

当指定为`localhost`时，默认从`/var/lib/kubelet/seccomp/`中搜索profile文件，详见`kubelet`的`--seccomp-profile-root`参数。

### selinux

~~~bash
setenforce 0
getenforce
sestatus
semanage
ls -Z
ps -efZ
chcon
chcon -v --type=httpd_sys_content_t /html
chcon -Rv --type=httpd_sys_content_t /html
restorecon -R /html
ausearch -m avc --start recent
setsebool -P virt_use_nfs 1
~~~

为Pod/容器设置selinux label

~~~yaml
...
securityContext:
  seLinuxOptions:
    level: "s0:c123,c456"
...
~~~

其中seLinuxOptions施加到volume上。一般情况下，只需设置level，其为Pod及其volumes设置
Multi-Category Security (MCS) label。
注意，一旦为Pod设置了MCS label，其它所有相同label的pod均可访问该Pod的volume。



## Docker操作

### 常用操作

```bash
docker system prune # 存储清理，可以加上参数 -a
docker system df    # 查看容器、镜像的存储用量
docker 重启是增加 live-restore 选项，可以降低重启docker的开销，重启docker daemon的时候容器不重启  除非bip这些变了。
docker push xxxx   # 将镜像push到私有registry，注意，nodeB希望从nodeA的registry获取镜像时，nodeA上必须先push到registry才行
docker pull xxxx   # 从registry上下载镜像至本地
docker run -it --name test --net container:6d054b93d4b1 openstack-keystone:D1101 bash
docker run -it --name test --net=host openstack-keystone:D1101 bash
docker rm -f $(docker ps | grep haproxy | awk '{print $1}')
docker build -t centos:base -f Dockerfile .
docker run -it --net=host centos:base bash     # 共享HOST网络
docker export $(docker create busybox:1.0.0) > busybox.tar # 提取镜像的rootfs文件
mkdir rootfs                                               # 提取镜像的rootfs文件
tar -C rootfs -xf busybox.tar                              # 提取镜像的rootfs文件
docker stats --no-stream   # 查看容器状态、资源使用情况
docker run -d -p 881 -v /root/sample/website:/var/www/html/website:rw --privileged=true test-img:1.0 nginx # 映射时需要加--privileged=true防止没有权限
docker attach xxxx    # 绑定到容器的stdio
docker exec d8c875f38278 bash -c "echo '1.2.3.4 hehe' >> /etc/hosts"   # 进入容器执行命令
docker inspect -f "{{json .Mounts}}" b2aed79fec98
docker inspect ${container} --format '{{.State.Pid}}'    # 获取容器的entrypoint进程pid
docker stats --format "{{.Name}} {{.MemPerc}}"
docker info -f '{{json .}}' | jq  #  格式化输出
docker load --input images.tar.gz
curl -v -X POST http://<ip>:2375/v1.26/images/load -T xxx.tar    #  调用docker接口load容器镜像
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

### Debug

```bash
kill -USR1 <docker-daemon-pid>   # 线程调用栈输出至/var/run/docker文件夹
kill -SIGUSR1 <containerd-pid>   # containerd调用栈输出至messages
```



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
EOF
systemctl daemon-reload
# 检查环境变量已配置
systemctl show --property Environment docker
# 重启docker使配置生效
systemctl restart docker
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



# Kubernetes





## 操作实例

### 常见操作

```bash
kubectl api-versions    #  查看API版本
# 注意，OpenShift的Controller-Manager和Scheduler组件整合为controller组件，并使用https://x.x.x.x:8444/healthz作为健康检查endpoint
curl -k https://10.125.30.224:8444/healthz  #  OpenShift平台查看controller的健康情况
kubectl get componentstatus # 查看集群组件信息
kubectl get --raw /api/v1/componentstatuses/controller-manager | jq
kubectl get --raw /apis/metrics.k8s.io/v1beta1/namespaces/openshift-sdn/pods/sdn-5bbcx | jq
kubectl get --raw /apis/custom.metrics.k8s.io/v1beta1/namespaces/default/pods/*/http_requests | jq
./kubectl --server=https://kubernetes/ --certificate-authority=/tmp/openssl/ca.crt --client-certificate=/tmp/openssl/client.crt --client-key=/tmp/openssl/client.key get pod
/opt/bin/kubectl -s 127.0.0.1:8888 get pod -o wide
/opt/bin/kubectl -s 127.0.0.1:8888 describe ep
/opt/bin/kubectl -s 127.0.0.1:8888 describe pod        # 查看Pod信息，定位问题
/opt/bin/kubectl -s 127.0.0.1:8888 cluster-info
/opt/bin/kubectl -s 127.0.0.1:8888 get services
/opt/bin/kubectl -s 127.0.0.1:8888 get rc
/opt/bin/kubectl -s 127.0.0.1:8888 get nodes -o=custom-columns=NAME:.metadata.name,IPS:.status.addresses    # 自定义信息的输出列
kubelet --help 2>&1 | less
# node状态为Ready,SchedulingDisabled时，手工开启调度：/opt/bin/kubectl -s 127.0.0.1:8888 uncordon 172.25.18.13
kubectl logs -p -c ruby web-1  # 查看Pod web-1中前一个ruby容器的日志
kubectl get svc mysql-node1 -o jsonpath='{.spec.clusterIP}' # 支持json格式解析
kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'
/opt/bin/kubectl -s 127.0.0.1:8888 delete -f /opt/bin/confFile-cluster/openstack-new-rc.yaml
kubectl get pod | grep -v NAME | awk '{print $1}'      # 查看所有Pod
kubectl get pod ceportalrc-n5sqd -o template --template={{.status.phase}}          # 查看Pod的运行状态
kubectl get node 172.25.18.24 -o template --template={{.status.nodeInfo.osImage}}  # 查看Node的操作系统信息
kubectl logs --namespace="kube-system" kube-dns-v17.1-rc1-27sj0 kubedns  # 查看容器的log
kubectl drain ${node} --delete-local-data --ignore-daemonsets --force
kubectl uncordon ${node}
kubectl label node 172.25.18.22 node=node3 # 给name为172.25.18.22的node打标签node: node3，kube-dns依赖于这个标签的。
kubectl label --overwrite node 172.25.19.119 nodeType=cellClus
kubectl label node 172.25.19.117 cellGrp-  # 删除节点的cellGrp标签
kubectl exec -it <pod名称> [-c <pod中容器名称>] <sh | bash> # k8s直接进容器
kubectl edit clusterrole   # 查看/修改RBAC
kubectl get events         # 查看事件
curl  -s 'http://172.25.19.109:8888/api/v1/namespaces/default/pods?labelSelector=app=rabbitmq-cluster,node=rabbit2' | jq '.items[].metadata.name' | tr -d '"'

# 通过curl直接访问Kubernetes的HTTPS RESTful API，注意：
# --cacert 指定CA中心的证书crt
# --cert   指定curl客户端的证书（公钥）
# --key    指定curl客户端的密码key（私钥），需要与--cert指定的证书对应
# 老平台支持
curl --cacert /root/openssl/ca.crt --cert /root/openssl/172.25.19.117-server.crt --key /root/openssl/172.25.19.117-server.key https://172.25.19.117:6443/api/
# 容器内支持
curl --cacert /root/openssl/ca.crt --cert /root/openssl/client.crt --key /root/openssl/client.key https://kubernetes/api/
# 老平台和Openshift新平台均支持
curl --cacert /root/openssl/ca.crt --cert /root/openssl/client.crt --key /root/openssl/client.key https://10.100.0.1/api/
# Openshift新平台支持
curl --cacert /root/openssl/ca.crt --cert /root/openssl/client.crt --key /root/openssl/client.key https://openshift-m2:8443/api/
NSS_SDB_USE_CACHE=yes curl --cacert /etc/origin/master/ca.crt --cert /etc/origin/master/admin.crt --key /etc/origin/master/admin.key  https://vip.cluster.local:8443/api/
NSS_SDB_USE_CACHE=yes curl --cacert /etc/origin/master/ca.crt --cert /etc/origin/master/admin.crt --key /etc/origin/master/admin.key  https://$(hostname):8443/apis/metrics.k8s.io/v1beta1?timeout=32s

# 通过token直接访问apiserver
kubectl get sa default -o yaml  # 找到 default sa的携带token信息的secrets
kubectl get secrets default-token-xxxxx -o jsonpath='{.data.token}' | base64 -d # 直接从secrets中获取TOKEN
kubectl get secrets -n cattle-system tls-cert -o jsonpath='{.data.cert\.pem}' | base64 -d > cert.pem    # 从secrets中复原证书和秘钥
NSS_SDB_USE_CACHE=yes curl -H "Authorization : Bearer ${TOKEN}" -k https://10.100.0.1/api/

# Pod（容器）里直接获取token的方法
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NSS_SDB_USE_CACHE=yes curl -s -H "Authorization : Bearer ${TOKEN}" -k https://10.100.0.1/api/v1/nodes?labelSelector=nodeType%3Dcontroller | jq -r .items[].metadata.name
```



### 客户端访问集群时context配置

```bash
# 注意，ca.crt、client.crt和client.key需要来自目标集群，例如配置中的deploy-cluster
kubectl config set-cluster deploy-cluster --server=https://${KUBE_APISERVER_IP_OR_DOMAINNAME}:${KUBE_APISERVER_PORT} --certificate-authority=./ca.crt --embed-certs=true
kubectl config set-credentials deploy-user --client-key=./client.key --client-certificate=./client.crt --embed-certs=true
kubectl config set-context deploy-context --cluster=deploy-cluster --user=deploy-user --namespace=default
# 切换到deploy-cluster集群，注意，后面的kubectl都是在deploy-cluster上操作
kubectl config use-context deploy-context
```



### ConfigMap使用

将配置/模板文件保存到configMap并提取出来

~~~
kubectl create configmap hehe --from-file=mysql-node-rc-template.yaml
kubectl get cm hehe -o jsonpath='{.data.mysql-node-rc-template\.yaml}'
~~~

创建加更新ConfigMap

~~~
kubectl create configmap -n default os-watchdog-config --from-file=i18n_zh.json --from-file=i18n_en.json -o yaml --dry-run | kubectl apply -f -
~~~

####

### 日志相关配置

```bash
--log-dir=/var/log/kubernetes --logtostderr=false --v=4
```

### 提升集群HA性能
kubelet设置 `--node-status-update-frequency` 参数，例如从默认值10s调整为5s，提升节点状态变化感知效率。
kube-controller-manager设置 `--node-monitor-grace-period` 参数，例如从默认值40s调整为16s，提升节点变化响应速度。



### 强制删除Pod

```bash
kubectl delete pods <pod> --grace-period=0 --force
```

### Pod中获取PodIP的方法

```bash
          env:
            - name: MYIP
              valueFrom:
                fieldRef:
                  fieldPath: status.podIP
            - name: RESOLVER_IP_ADDR
              valueFrom:
                fieldRef:
                  fieldPath: status.hostIP
```
详见 Pod Preset, Expose Pod Information to Containers Through Environment Variables and Through Files.
仅kubernetes v1.8+版本支持。

### emptyDir在宿主机上的路径

```bash
/var/lib/kubelet/pods/<pod uuid>/volumes/kubernetes.io~empty-dir
```



### FC存储多路径的PV配置

```bash
apiVersion: v1
kind: PersistentVolume
metadata:
  name: hehe-pv
spec:
  capacity:
    storage: 10Gi
  accessModes:
    - ReadWriteOnce
  volumeMode: Block
  persistentVolumeReclaimPolicy: Retain
  fc:
    targetWWNs: ["21120002ac012e3b", "20110002ac012e3b"]
    lun: 9
    fsType: ext4
    readOnly: false
```
WWN和lun在 /dev/disk/by-path 中获取，格式为 `/dev/disk/by-path/pci-<IDENTIFIER>-fc-0x<WWN>-lun-<LUN#>`，例如
```bash
[root@devops1 by-path]# pwd
/dev/disk/by-path
[root@devops1 by-path]# ls | grep fc
...
pci-0000:18:00.0-fc-0x21120002ac012e3b-lun-9
...
pci-0000:18:00.1-fc-0x20110002ac012e3b-lun-9
```
由于存储多路径，同一个LUN对应填写两个WWN，上述LUN-9对应 WWN 21120002ac012e3b 和 WWN 20110002ac012e3b 。



# Golang

## 常用操作

```bash
# 编译静态链接的可执行文件
CGO_ENABLED=0 go build -o harbor_ui github.com/vmware/harbor/src/ui

# 使用vendor
go build -mod vendor ./pkg/agent
```







# Special column



## Git



### 常用操作

```bash
git push -u origin maxscale-2.1.7       # push的同时，设置默认的远程仓库分支
git branch -vv
git clone -b maxscale-2.1.7 https://github.com/ytinirt/test.git
git tag -a v1.4 -m "my version 1.4"     # 创建Annotated Tag
git tag -a v1.2 deadbeef                # 根据历史commit，创建Tag
git tag v1.4-lw                         # 创建Lightweight Tag
git push origin v1.5                    # 将本地Tag push到remote server
git push origin --tags                  # 批量上传本地所有未push的Tag到remote server
git tag
git show v1.4
git log --pretty=oneline
# 直接checkout一个Tag时，会将repo置于“detached HEAD”状态，为此，可根据Tag创建Branch，在该Branch上修改bug再打Tag
git checkout -b version2 v2.0.0
git branch -d -r origin/feature/init    # 删除remote分支
git reset HEAD~                         # 撤销还未push的commit
git rm file                             # 删除文件
git clean -xdf .                        # 清理临时文件
git stash                               # 暂存修改
git stash pop                           # 重新实施暂存的修改
git config --global core.autocrlf=input # windows拉取代码时候换行符保持和仓库一样，提交代码时候换行符自动转换成 \n
git commit --signoff                    # 带上Signed-Off信息
git commit --signoff --amend            # 为上一个commit追加Signed-Off信息
git rev-parse --show-toplevel           # 获取repo根目录
git checkout -b systemd-mac-assignment bed5b7ef6c

# 为git设置代理
git config --global https.proxy 'http://a.b.c:8080'
git config --global http.proxy 'http://a.b.c:8080'
```



## Makefile

### Makefile文件

在Makefile文件中使用shell函数

```bash
# 使用shell函数
tar -zcf os-nfs-v1-$$(date +"%y%m%d%H%M")-M1.tar.gz os-nfs
```



### cmake

```bash
# 查看配置项信息
cmake ../mysql-server-mysql-5.7.20/ -LH
```





## Etcd

常见操作

```bash
etcdctl ls get
etcdctl member list
etcdctl --debug cluster-health     # 能看到使用的API
etcdctl member list                # 显示成员信息
etcdctl mk /hehe/xixi "haha"
etcdctl update key 'val'
etcdctl rm key
etcdctl 2>/dev/null -o extended get /coreos.com/network/subnets/10.101.13.0-24

# 统计度量信息
/metrics
# debug信息
/debug/vars
```



### v3常见操作

获取所有key

```bash
ETCDCTL_API=3 /opt/bin/etcdctl-bin/etcdctl get / --prefix --keys-only --cacert=/root/cfssl/ca.pem --cert=/root/cfssl/node-client.pem --key=/root/cfssl/node-client-key.pem
```

获取key数量

```bash
ETCDCTL_API=3 /opt/bin/etcdctl-bin/etcdctl get / --prefix --keys-only --cacert=/root/cfssl/ca.pem --cert=/root/cfssl/node-client.pem --key=/root/cfssl/node-client-key.pem 2>/dev/null | grep -v ^$ | wc -l
```

查看etcd节点信息

```bash
ETCDCTL_API=3 /opt/bin/etcdctl-bin/etcdctl --cacert=/root/cfssl/ca.pem --cert=/root/cfssl/node-client.pem --key=/root/cfssl/node-client-key.pem -w table endpoint status 2>/dev/null
```

遍历etcd中存储的所有数据

```bash
for i in $(ETCDCTL_API=3 etcdctl --cert="/etc/etcd/peer.crt" --key="/etc/etcd/peer.key" --cacert="/etc/etcd/ca.crt" --endpoints https://$(hostname):2379  get / --prefix --keys-only 2>/dev/null)
do
  ETCDCTL_API=3 etcdctl --cert="/etc/etcd/peer.crt" --key="/etc/etcd/peer.key" --cacert="/etc/etcd/ca.crt" --endpoints https://$(hostname):2379 get ${i} 2>/dev/null
done
```

alarm
```bash
ETCDCTL_API=3 /opt/bin/etcdctl-bin/etcdctl --cacert=/root/cfssl/ca.pem --cert=/root/cfssl/node-client.pem --key=/root/cfssl/node-client-key.pem alarm list
```

### v2 API

参见`https://coreos.com/etcd/docs/latest/v2/api.html`

```bash
# 查询现有keys
curl -s http://os-param-svc.default.svc:2379/v2/keys | jq
# 新建key
curl -i -X PUT http://os-param-svc.default.svc:2379/v2/keys/testconfig?value={configValue}
# 查看新建的key
curl -s os-param-svc.default.svc:2379/v2/keys/testconfig | jq
# watch新建的key，GET操作阻塞在那里直到key的value有变化
curl -s os-param-svc.default.svc:2379/v2/keys/testconfig?wait=true
# 删除key
curl -X DELETE http://os-param-svc.default.svc:2379/v2/keys/testconfig
```

### 修复故障节点

前提：

1. etcd集群处健康状态
2. 异常节点此前属于该集群，且集群IP地址未变化

将异常节点从集群移除

```bash
systemctl stop etcd2 # 异常节点上执行
rm –rf /NODEX.etcd   # 删除异常节点上etcd数据目录
/opt/bin/etcdctl remove member-id # 正常节点上执行
```

将异常节点重新加入集群

```bash
/opt/bin/etcdctl add NODEX http://异常节点IP:2380      # 正常节点上执行
修改/etc/sysconfig/kube-etcd-cluster配置文件中 ETCD_INITIAL_CLUSTER_STATE=new 为 ETCD_INITIAL_CLUSTER_STATE=existing
systemctl start etcd2  # 异常节点上执行，启动异常节点上etcd2的服务
/opt/bin/etcdctl member list  # 正常节点上执行，检查故障是否恢复
/opt/bin/etcdctl cluster-health # 检查集群状态是否健康
修改/etc/sysconfig/kube-etcd-cluster配置文件中 ETCD_INITIAL_CLUSTER_STATE=existing 为 ETCD_INITIAL_CLUSTER_STATE=new
```

### 快照备份（v3+支持）
```bash
ETCDCTL_API=3 etcdctl snapshot save backup.db
ETCDCTL_API=3 etcdctl --write-out=table snapshot status backup.db
```

### v2全量备份
```bash
etcdctl backup --data-dir="/path/to/data/" --backup-dir="/path/to/backup/"
```



### 调优

参考

- https://github.com/coreos/etcd/blob/v3.1.6/Documentation/tuning.md
- https://coreos.com/etcd/docs/latest/tuning.html

影响etcd性能的主要因素：

* 网络延迟
* Disk IO性能

**时间参数**

HeartbeatInterval: 主节点的心跳周期（默认100ms），最佳实践建议采用节点间RTT（采用ping获取）的最大平均值。
ElectionTimeout: 超过该时间（默认1000ms）未收到主节点的心跳后，从节点会启动选举操作，至少是 max {(RTT x 10), (HeartbeatInterval x [5, 10])}

**快照Snapshot**

为避免WAL日志过大，etcd周期性打快照，用以记录当前系统状态并删除旧WAL日志，以节省空间。
快照操作代价高昂，默认情况下每达到10K次修改便执行快照操作，当etcd内存或磁盘利用率较高时，可考虑降低打快照的阈值，例如改为5K。

**Disk IO性能**

Etcd集群对Disk IO性能、延迟特别敏感。由于WAL日志的持久化，fsync操作的延迟时间对Etcd特别关键。Disk性能出现问题时，很可能导致主
节点心跳丢失、请求超时、暂时的leader loss等问题，对Etcd集群健康和稳定性带来巨大挑战。

**使用ionice修改IO优先级**

使用ionice提升etcd进程的IO优先级，避免受到其它任务/进程的影响：
```bash
ionice -c2 -n0 -p $(pgrep -w etcd3)
```
执行如下操作，批量修改
```bash
cat <<EOF >/opt/bin/common/etcd-io-tuning.sh
#!/bin/bash

pids=\$(/usr/bin/pgrep -w etcd3)
/usr/bin/ionice -c2 -n0 -p \${pids}
EOF

chmod a+x /opt/bin/common/etcd-io-tuning.sh

sed -i '/ExecStart=/a\ExecStartPost=-/opt/bin/common/etcd-io-tuning.sh' /usr/lib/systemd/system/etcd2.service
systemctl daemon-reload
```

**网络**

当大量客户端请求达到Etcd集群时，可能降低Etcd集群内部节点通信效率，甚至导致内部网路拥塞使集群不健康。
通过tc，将客户端请求(client requests)和集群内部节点请求(peer requests)区分开来，保证peer requests优先，示例如下：
```bash
tc qdisc add dev eth0 root handle 1: prio bands 3
tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip sport 2380 0xffff flowid 1:1
tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip dport 2380 0xffff flowid 1:1
tc filter add dev eth0 parent 1: protocol ip prio 2 u32 match ip sport 2379 0xffff flowid 1:1
tc filter add dev eth0 parent 1: protocol ip prio 2 u32 match ip dport 2379 0xffff flowid 1:1
```
施加网络延迟
~~~
# 模拟eth0网卡延迟1000ms 约30%延迟100ms
tc qdisc add dev eth0 root netem delay 1000ms 100ms 30%
# 删除延迟配置
tc qdisc delete dev eth0 root netem delay 1000ms 100ms 30%
~~~
施加网络丢包
~~~
# 模拟丢包10%
tc qdisc add dev eth0 root netem loss 10%
# 模拟丢包10% 有50%成功率
tc qdisc add dev eth0 root netem loss 10% 50%
~~~

### 错误类型说明

**Minor followers failure**

> When fewer than half of the followers fail, the etcd cluster can still accept requests and make progress without any major
> disruption. For example, two follower failures will not affect a five member etcd cluster’s operation. However, clients will
> lose connectivity to the failed members. Client libraries should hide these interruptions from users for read requests by
> automatically reconnecting to other members. Operators should expect the system load on the other members to increase due to
> the reconnections.

**Leader failure**

> When a leader fails, the etcd cluster automatically elects a new leader. The election does not happen instantly once the leader
> fails. It takes about an election timeout to elect a new leader since the failure detection model is timeout based.
> During the leader election the cluster cannot process any writes. Write requests sent during the election are queued for
> processing until a new leader is elected.
> Writes already sent to the old leader but not yet committed may be lost. The new leader has the power to rewrite any
> uncommitted entries from the previous leader. From the user perspective, some write requests might time out after a new leader
> election. However, no committed writes are ever lost.
> The new leader extends timeouts automatically for all leases. This mechanism ensures a lease will not expire before the granted
> TTL even if it was granted by the old leader.

**Majority failure**

> When the majority members of the cluster fail, the etcd cluster fails and cannot accept more writes.
> The etcd cluster can only recover from a majority failure once the majority of members become available. If a majority of
> members cannot come back online, then the operator must start disaster recovery to recover the cluster.
> Once a majority of members works, the etcd cluster elects a new leader automatically and returns to a healthy state. The new
> leader extends timeouts automatically for all leases. This mechanism ensures no lease expires due to server side unavailability.

**Network partition**

> A network partition is similar to a minor followers failure or a leader failure. A network partition divides the etcd cluster
> into two parts; one with a member majority and the other with a member minority. The majority side becomes the available
> cluster and the minority side is unavailable; there is no “split-brain” in etcd.
> If the leader is on the majority side, then from the majority point of view the failure is a minority follower failure. If the
> leader is on the minority side, then it is a leader failure. The leader on the minority side steps down and the majority side
> elects a new leader.
> Once the network partition clears, the minority side automatically recognizes the leader from the majority side and recovers
> its state.

**Failure during bootstrapping**

> A cluster bootstrap is only successful if all required members successfully start. If any failure happens during bootstrapping,
> remove the data directories on all members and re-bootstrap the cluster with a new cluster-token or new discovery token.
> Of course, it is possible to recover a failed bootstrapped cluster like recovering a running cluster. However, it almost always
> takes more time and resources to recover that cluster than bootstrapping a new one, since there is no data to recover.



## tcpdump

网络报文抓包工具。

常用命令：

```bash
# 各种复杂过滤规则示例
tcpdump -i lo 'tcp dst port 4194 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' -A
tcpdump -i docker0 "dst 10.100.146.23 or dst 10.100.42.177 or dst 10.100.58.78" -nnq  | grep -v "length 0" | awk '{print $3}' | sed "s/\./ /g" | awk '{print $1"."$2"."$3"."$4}'
tcpdump -i eth0 '(tcp dst port 5005 or tcp dst port 19000) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' -A
tcpdump -i eth0 'tcp and (ip src 10.101.13.21) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' -A

# TCP报文是 GET 请求
tcpdump -i eth0 '(ip src 10.101.13.21) and (tcp[(tcp[12]>>2):4] = 0x47455420)'
# TCP报文是 POST 请求
tcpdump -i eth0 '(ip src 10.101.13.21) and (tcp[(tcp[12]>>2):4] = 0x504F5354)'
# TCP报文是 PUT 请求
tcpdump -i eth0 '(ip src 10.101.13.21) and (tcp[(tcp[12]>>2):4] = 0x50555420)'
# TCP报文是 DELETE 请求
tcpdump -i eth0 '(ip src 10.101.13.21) and (tcp[(tcp[12]>>2):4] = 0x44454C45)'
# TCP报文是 HTTP 应答
tcpdump -i eth0 '(ip dst 10.101.13.21) and (tcp[(tcp[12]>>2):4] = 0x48545450)'

# 谁在应答findCompute这个API
tcpdump -i docker0 '(tcp[(tcp[12]>>2):4] = 0x47455420)' -A  | grep "GET\|IP" | grep -B 1 "findCompute"

# 抓取报文并保存到本地
tcpdump -i eth0 port 8443 -w hehe.pcap -B 409600

# 常用的标识
# -N          不带详细的DNS域名
# -w file     输出抓包信息至文件
# -s0         抓取完整的数据包
# -q          显示尽量少的协议信息
# -t          不显示时间戳
```

### tcpdump和libpcap常用规则

```bash
dns.qry.name contains "devops"      # DNS请求过滤
```



## Openstack

### 常用操作

```bash
nova hypervisor-list
nova hypervisor-show <uuid>
openstack compute service set --disable <host>
```

### nova compute健康状态检查

进入compute容器后，首先
`source ~/admin-openrc.sh`
获取配置信息，然后根据

```bash
nova service-list | grep "nova-compute" | grep "$HOSTNAME" | grep -q 'down'
cinder service-list | grep "cinder-volume" | grep "$HOSTNAME" | grep -q 'down'
```
查看计算和存储控制实体是否处于up状态。

### rally测试中TCP端口耗尽问题解决

requests在创建请求连接的时候，连接没有复用，导致端口centos的端口全部用完，不能再继续创建连接。
修改了`sysctl.conf`里面的参数，添加一个这个配置应该就没有问题了`net.ipv4.tcp_tw_recycle = 1`。

还存在另外一个参数`net.ipv4.tcp_tw_reuse`，相较`net.ipv4.tcp_tw_recycle`更安全，允许reuse处于`TIME_WAIT`状态的套接字。
而在LB场景时，使用`net.ipv4.tcp_tw_recycle`有副作用。具体的在LB的public-facing服务器上，当recycle开启后，NAT设备后面的服务器无法区分不同客户端的新连接。
且从Linux-4.12开始，`net.ipv4.tcp_tw_recycle`参数被废弃。



## OpenShift and OKD

### 常用操作

权限操作：

```bash
oc adm policy add-scc-to-user privileged -z default -n <namespace>
oc adm policy add-scc-to-user anyuid -z istio-pilot-service-account -n istio-system
oc adm policy add-scc-to-user anyuid -z istio-sidecar-injector-service-account -n istio-system
oc adm policy add-cluster-role-to-user cluster-reader system:serviceaccount:<namespace>:default
oc adm policy add-cluster-role-to-user cluster-reader -z default -n <namespace_name>
```

自定义router服务端口：

```bash
oc adm policy add-scc-to-user hostnetwork -z router
oc adm router router --ports='10080:10080,10443:10443' --replicas=0 --service-account=router

oc edit dc/router # 修改环境变量 ROUTER_SERVICE_HTTPS_PORT 和 ROUTER_SERVICE_HTTP_PORT
# 或者执行
oc set env dc/router ROUTER_SERVICE_HTTP_PORT=10080 ROUTER_SERVICE_HTTPS_PORT=10443

oc scale dc/router --replicas=3

# 可能需要执行
iptables -A INPUT -p tcp --dport 10080 -j ACCEPT
iptables -A INPUT -p tcp --dport 10443 -j ACCEPT
```

运维操作：

```bash
# 用户登录
oc login https://vip.cluster.local:8443 -u system:admin

# 日志查看
master-logs api api     # 查看apiserver的日志
master-logs controllers controllers     # 查看controller服务的日志

# 服务重启
master-restart api      # 重启api服务
master-restart controllers # 重启controller服务

# 检查cni服务端是否正常
echo 'test' | socat - UNIX-CONNECT:/var/run/openshift-sdn/cni-server.sock
```



访问webconsole：

1. 将集群中任一节点`/etc/hosts`内的记录添加到电脑的`C:\Windows\System32\drivers\etc\hosts`中
2. 访问`https://vip.cluster.local:8443/`
3. 用户名和密码：`system/admin`或者`admin/system`



统计平台内存资源开销：

```bash
ps -eo 'pid,rss,comm' | grep -i 'openshift\|hyperkube\|ovs\|origin\|etcd\|dockerd' | awk '{a+=$2}END{print a}'
```



### 官方yum源

地址`http://mirrors.xxx.com/centos/7/paas/x86_64/openshift-origin/`

```bash
cat <<EOF >/etc/yum.repos.d/openshift-origin.repo
[openshift-origin]
name=Extra Packages for Enterprise Linux 7 - $basearch
baseurl= http://mirrors.xxx.com/centos/7/paas/x86_64/openshift-origin/
enabled=1
gpgcheck=0
EOF
```





## Harbor

### 手动清理镜像

操作步骤如下：

1. 进入 harbor管理界面： https://${ip}:11443  登陆：admin/Harbor12345

2. 在harbor镜像页面内删除镜像，注意只是删除仓库中记录

3. 进入registry 容器内

   ```bash
   docker exec {container_id} /usr/bin/registry garbage-collect /etc/docker/registry/config.yml
   docker restart {container_id}
   ```



## Rancher

### 通过API访问Rancher
API-key
~~~bash
curl -k -H 'Authorization: Bearer token-12345:67890' https://a.b.c/v3
~~~

### 在Air Gap环境中以HA方式部署Rancher
参见文档

```
https://rancher.com/docs/rancher/v2.x/en/installation/other-installation-methods/air-gap/install-rancher/
```

在够访问公网的电脑上

```bash
helm init -c
helm repo add rancher-stable https://releases.rancher.com/server-charts/stable
helm fetch rancher-stable/rancher
helm template ./rancher-<VERSION>.tgz --output-dir . \
    --name rancher \
    --namespace cattle-system \
    # 用于配置ingress中host，若不同ingress方式对外直接暴露Rancher Server Portal，可不配置
    --set hostname=<RANCHER.YOURDOMAIN.COM> \
    # 目前将rancher需要的所有镜像静态load到所有节点，因此不需要该配置
    --set rancherImage=<REGISTRY.YOURDOMAIN.COM:PORT>/rancher/rancher \
    --set ingress.tls.source=secret \
    # 使用私有CA证书时（例如使用OpenShift集群的/etc/origin/master/ca.crt），必须配置
    --set privateCA=true \
    # Available as of v2.2.0, set a default private registry to be used in Rancher
    --set systemDefaultRegistry=<REGISTRY.YOURDOMAIN.COM:PORT> \
    # Available as of v2.3.0, use the packaged Rancher system charts
    --set useBundledSystemChart=true
```
将上述经过渲染的`rancher`文件夹传递到K8s集群上。

K8s集群上操作：

1. 创建命名空间

```bash
kubectl create namespace cattle-system
```
2. 签发Rancher Server使用的证书，使用OpenShift的CA，为Rancher Server签发证书。**注意**，hostnames中需包含外部访问Rancher Server时可能的域名和IP地址。

```bash
oc adm ca create-server-cert --hostnames='vip.cluster.local,10.125.30.224,10.125.30.222,10.125.30.223,10.125.30.220' --cert=cert.pem --key=key.pem --expire-days=1825 --signer-cert=/etc/origin/master/ca.crt --signer-key=/etc/origin/master/ca.key --signer-serial=/etc/origin/master/ca.serial.txt
```
3. 创建Secret

```bash
cp /etc/origin/master/ca.crt cacerts.pem
# 创建CA、CERT和KEY的secret，供Rancher Server使用
kubectl -n cattle-system create secret generic tls-ca   --from-file=cacerts.pem
kubectl -n cattle-system create secret generic tls-cert   --from-file=cert.pem
kubectl -n cattle-system create secret generic tls-key   --from-file=key.pem
```
4. 赋予mknod权限，修改deployment.yaml，增加Linux Capabilities MKNOD

```bash
        securityContext:
          capabilities:
            add: ["MKNOD"]
```
5. 挂载CA、证书、密钥，修改deployment.yaml，将之前的CA、CERT和KEY挂载到Rancher Server中

```bash
        volumeMounts:
        # Pass CA cert into rancher for private CA
        - mountPath: /etc/rancher/ssl/cacerts.pem
          name: tls-ca-volume
          subPath: cacerts.pem
          readOnly: true
        - mountPath: /etc/rancher/ssl/cert.pem
          name: tls-cert-volume
          subPath: cert.pem
          readOnly: true
        - mountPath: /etc/rancher/ssl/key.pem
          name: tls-key-volume
          subPath: key.pem
          readOnly: true
      volumes:
      - name: tls-ca-volume
        secret:
          defaultMode: 0400
          secretName: tls-ca
      - name: tls-cert-volume
        secret:
          defaultMode: 0400
          secretName: tls-cert
      - name: tls-key-volume
        secret:
          defaultMode: 0400
          secretName: tls-key
```
6. 部署Rancher Server，根据需要暴露`svc/rancher`服务

```bash
kubectl -n cattle-system apply -R -f ./rancher
```
7. OpenShift环境上为启动监控扫清障碍

```bash
kubectl create namespace cattle-prometheus
oc adm policy add-scc-to-user anyuid -z operator-init-cluster-monitoring -n cattle-prometheus
oc adm policy add-scc-to-user anyuid -z operator-init-monitoring-operator -n cattle-prometheus
oc adm policy add-scc-to-user anyuid -z cluster-monitoring -n cattle-prometheus
oc adm policy add-scc-to-user privileged -z exporter-node-cluster-monitoring -n cattle-prometheus
oc adm policy add-scc-to-user anyuid -z exporter-kube-state-cluster-monitoring -n cattle-prometheus
```

## nginx

Nginx请求日志分析，查看哪个IP的访问量大
```bash
cat access.log | grep "03/Jun" | awk '{print $1}' | sort | uniq -c | sort -nrk 1 | head -n 10
```



## haproxy

### 使用socat操作UNIX domain套接字

```bash
socat readline /var/run/haproxy.stat
# prompt提示符>
> help
> set timeout cli 1d
> show table
> show table http

# 单次操作
echo 'show table web' | socat stdio /var/run/haproxy.stat
# 持续请求
watch -n 1 -d 'echo "show table web" | socat stdio /var/run/haproxy.stat'
```





## keepalived

### keepalived背后的vrrp
vrrp的IP协议号为112

```bash
tcpdump -i eth0 'ip proto 112'
```



## Swagger

### 使用swagger-ui

1. 编写api文档`/tmpfs/swagger.yml`
2. 准备镜像`docker pull swaggerapi/swagger-ui:latest`
3. 启动服务`docker run -p 8080:8080 -e SWAGGER_JSON=/hehe/swagger.yml -v /tmpfs:/hehe --name swagger-ui swaggerapi/swagger-ui`

## memcached

使用工具`memcached-tool`：

```bash
# 关注bytes和get_hits和get_miss
memcached-tool svc:11211 stats
```



## mysql



### 数据库操作

#### 常用操作

```bash
mysql -u xxx -p xxx
show databases
use xxx
select * from xxx
mysqladmin -uroot -ppassword status  # 显示数据库信息，其中包括当前会话连接数。
show status like '%max_use%';        # 查看数据库当前连接数。
describe xxx;                        # 显示表的colum信息
stop slave;                          # 停止slave节点
start slave;                         # 开始slave节点
show slave status\G                  # 查看Slave节点信息
show master status\G                 # 查看Slave节点信息
show create table xxx                # 查看创建表使用的DDL语句
show slave hosts;                    # 在master上查看slave的基本信息
show processlist;                    # 显示process
show full processlist;               # 显示所有process
show status like "%wsrep%";          # PXC数据库集群状态信息
select sysdate(3);                   # 通过sysdate函数获取系统时间
select TABLE_SCHEMA,TABLE_NAME,CREATE_TIME,UPDATE_TIME from information_schema.TABLES where ENGINE = 'InnoDB' and UPDATE_TIME != 'NULL';
curl -4 --connect-timeout 5 -s param-service:2379/v2/keys/component/plat/mysql/master|jq .node.value -r # 在数据库Pod中获知真正的MySQL主节点
mysql –uroot –ppassword –e "stop slave;reset slave;reset slave all;"     # 在真正的主节点上执行，修复多主问题
SELECT @@server_id, @@read_only;    # 查看本地变量
drop trigger db.trigger_name;       # 在information_schema.TRIGGERS中查看所有触发器信息
drop procedure db.procedure_name;   # 在mysql.proc中查看所有存储过程
# 当slave上执行SQL出错，Slave_SQL_Running为No时，在该slave上执行如下语句恢复
mysql -uroot -ppassword -e "stop slave; set global sql_slave_skip_counter=1;start slave;"
mysqldump -uroot -ppassword -h127.0.0.1 --all-databases >mysqlDump_`date +"%Y%m%d_%H%M%S_%s"`.sql    #  数据库备份操作
purge binary logs before '2018-03-23 19:00:00'; # 删除binlog
flush logs; # 刷新logs
read_only # 数据库只读选项
max_connections # 最大连接数
innodb_buffer_pool_size # innodb引擎缓存池大小
sync_binlog # binlog同步（至disk）的方式，为0表示不记录到disk，大于0时表示sync_binlog次commit后会同步至disk上的binlog日志
relay_log_space_limit # 设置relay log日志上限，其不应小于max_relay_log_size和max_binlog_size
relay_log_purge # 自动清理已处理完成的relay log，但mha主动的故障切换时依赖relay log，因此需要关闭该功能
expire_logs_days    # binlog过期时间，仅对binlog有效，对relay log无效
slave_net_timeout # 考虑主从复制假死，主节点挂了，从节点感知不到，会造成切换失败，因此该时间必须缩短
```

#### 数据库master节点操作

```bash
mysql -uos_admin -ppassword -e "show master status" # 查看binlog文件及位置，分别记录至param-service:2379/v2/keys/component/plat/${CELL_NAME}mysql/{master,file,pos}
mysql -uos_admin -ppassword -e "set global read_only=0;set global sync_binlog=10;" # 主节点基本配置
mysql -uos_admin -ppassword -e "stop slave;reset slave;reset slave all;" # 如果当前节点还是slave，即show slave status有信息，则停止当前节点slave服务
```

#### 数据库slave节点操作

```bash
# 从param-service:2379/v2/keys/component/plat/${CELL_NAME}mysql/{master,file,pos}分别获取主节点、binlog文件、文件位置信息
mysql -uos_admin -ppassword -e "set global read_only=1;set global sync_binlog=0;" # 从节点基本配置
# 如果当前slave status有效，且主节点ssh失联
mysql -uos_admin -ppassword -e "show processlist;"|grep "Slave has read all relay log"|awk '{print $1,$6}' # 找到relaylog同步线程
mysql -uos_admin -ppassword -e "kill ${sql_thread_id};" # 终结同步线程
# 如果当前slave status有效，且主节点ssh正常，重启下slave
mysql -uos_admin -ppassword -e "stop slave;"
mysql -uos_admin -ppassword -e "start slave;"
# 正常设置从节点
mysql -uos_admin -ppassword -e "reset slave;"
mysql -uos_admin -ppassword -e "stop slave;change master to master_host='$1',master_user='${CLUSTER_USER}',master_password='${CLUSTER_PWD}',master_log_file='$2',master_log_pos=$3;"
mysql -uos_admin -ppassword -e "start slave;"
```

#### 重置slave上master binlog的位置
当恢复快照后，往往遇到没有master的情况：

```bash
[root@xxx]# for i in $(pod | grep Running | grep maxscale | awk '{print $2}'); do kubectl exec -i $i maxadmin list servers; done
Servers.
-------------------+-----------------+-------+-------------+--------------------
Server             | Address         | Port  | Connections | Status
-------------------+-----------------+-------+-------------+--------------------
server1            | os-mysql-node1  |  3306 |           0 | Slave, Running
server2            | os-mysql-node2  |  3306 |           0 | Slave, Running
server3            | os-mysql-node3  |  3306 |           0 | Running
-------------------+-----------------+-------+-------------+--------------------
```

解决办法为重置slave上master binlog的位置：

```bash
stop slave;reset slave all;change master to master_host='os-mysql-node3',master_log_file='mysql-bin.000007',master_log_pos=4,master_user='os_admin',master_password='password';start slave;
```

#### 数据库读写分离主从同步延迟测试SQL语句
```bash
create database test;
create table test.t1 (name char(10), primary key (name));

insert into test.t1 values('hehe');
select * from test.t1;
delete from test.t1 where name = 'hehe';
```

#### 查看从数据库服务器信息
```bash
[root@xxx ~]# mysql -uroot -ppassword -h127.0.0.1 -P4001 -e 'show slave status\G'
*************************** 1. row ***************************
               Slave_IO_State: Waiting for master to send event
                  Master_Host: mysql-node2
                  Master_User: repl
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: mysql-bin.000452
          Read_Master_Log_Pos: 595086
               Relay_Log_File: mysql-relay-bin.000011
                Relay_Log_Pos: 584105
        Relay_Master_Log_File: mysql-bin.000452
             Slave_IO_Running: Yes          #  Slave_IO_Running和Slave_SQL_Running是判断slave是否运行的关键信息，只有当它们
            Slave_SQL_Running: Yes          #  都是Yes时，才认为该slave处运行中
              Replicate_Do_DB:
          Replicate_Ignore_DB: information_schema,performance_schema
           Replicate_Do_Table:
       Replicate_Ignore_Table:
      Replicate_Wild_Do_Table:
  Replicate_Wild_Ignore_Table:
                   Last_Errno: 0
                   Last_Error:
                 Skip_Counter: 0
          Exec_Master_Log_Pos: 595086
              Relay_Log_Space: 746337
              Until_Condition: None
               Until_Log_File:
                Until_Log_Pos: 0
           Master_SSL_Allowed: No
           Master_SSL_CA_File:
           Master_SSL_CA_Path:
              Master_SSL_Cert:
            Master_SSL_Cipher:
               Master_SSL_Key:
        Seconds_Behind_Master: 0
Master_SSL_Verify_Server_Cert: No
                Last_IO_Errno: 0
                Last_IO_Error:
               Last_SQL_Errno: 0
               Last_SQL_Error:
  Replicate_Ignore_Server_Ids:
             Master_Server_Id: 26469        #  只有当Slave_IO_Running为Yes时，才能获取到master的id
                  Master_UUID: 16172385-4b58-4d90-8462-2157c1c8dd9d
             Master_Info_File: /var/lib/mysql/master.info
                    SQL_Delay: 0
          SQL_Remaining_Delay: NULL
      Slave_SQL_Running_State: Slave has read all relay log; waiting for more updates
           Master_Retry_Count: 86400
                  Master_Bind:
      Last_IO_Error_Timestamp:
     Last_SQL_Error_Timestamp:
               Master_SSL_Crl:
           Master_SSL_Crlpath:
           Retrieved_Gtid_Set:
            Executed_Gtid_Set:
                Auto_Position: 0
         Replicate_Rewrite_DB:
                 Channel_Name:
           Master_TLS_Version:
```



### DBA相关

#### 获取 InnoDB_Buffer_Pool_Size 推荐值

```mysql
SELECT CEILING(Total_InnoDB_Bytes*1.6/POWER(1024,3)) RIBPS FROM
(SELECT SUM(data_length+index_length) Total_InnoDB_Bytes
FROM information_schema.tables WHERE engine='InnoDB') A;
```


#### 获取 InnoDB Buffer Pool实际使用情况

```mysql
SELECT (PagesData*PageSize)/POWER(1024,3) DataGB FROM
(SELECT variable_value PagesData
FROM information_schema.global_status
WHERE variable_name='Innodb_buffer_pool_pages_data') A,
(SELECT variable_value PageSize
FROM information_schema.global_status
WHERE variable_name='Innodb_page_size') B;
```

#### 获取pool size 和 数据库内存使用参考值（mysql在800连接但不执行任何sql时需要的内存）
```mysql
select @@innodb_buffer_pool_size;
select (@@key_buffer_size + @@query_cache_size + @@tmp_table_size + @@innodb_buffer_pool_size + @@innodb_log_buffer_size
          + 800 * (@@read_buffer_size + @@read_rnd_buffer_size + @@sort_buffer_size+ @@join_buffer_size + @@binlog_cache_size + @@thread_stack))/1024/1024;
```

#### 查询临时表的创建

```mysql
show global status like '%Created_tmp%';
```

#### 临时表使用的内存大小
```mysql
show global variables like 'max_heap_table_size';
```

#### mysqld内存高使用量分析
```
  A. 配置参数检查
     全局变量，仅申请一次：
       query_cache_size (1048576)
       key_buffer_size (134217728)
     全局默认，per-session变量，当会话需要时才申请，且不会复用，每用到都申请：
       read_buffer_size (131072)
       sort_buffer_size (262144)
       join_buffer_size (262144)
     TODO:
     innodb_buffer_pool_size (8053063680)
     innodb_log_buffer_size (8388608)
     innodb_sort_buffer_size (1048576)
     max_connections (10000)
     read_rnd_buffer_size (262144)
     tmp_table_size (16777216)
     注意，并非所有的per-thread分配内存都可以配置参数，例如存储过程“stored procedures”，它能使用的内存没有上限。
```





### SQL语句实例

```mysql
UPDATE cloudce_module_zone SET `uuid`= LEFT(`uuid`,7) WHERE LENGTH(uuid)>7; # 截取7位字符
```





## maxscale

maxadmin常用命令（使用时记得在如下命令前加上maxadmin）：

```bash
list clients - List all the client connections to MaxScale
list dcbs - List all active connections within MaxScale
list filters - List all filters
list listeners - List all listeners
list modules - List all currently loaded modules
list monitors - List all monitors
list services - List all services
list servers - List all servers
list sessions - List all the active sessions within MaxScale
list threads - List the status of the polling threads in MaxScale
list commands - List registered commands

{enable | disable} log-priority {info | debug | notice | warning}
```



## mha



## PostgreSQL

常用操作命令

```bash
psql -U postgres
\l      # 查看数据库
\u      # 查看user
```



## SQLite

```sqlite
sqlite3 dbusers.db

.schema
select * from mysqlauth_users;
select password from mysqlauth_users where user='u' and ( 'dddd' = host or 'dddd' like host ) and (anydb = '1' OR 'hehe' = '' OR 'hehe' LIKE db) limit 1;
.quit
```



## Redis

连接redis服务器 `redis-cli -p 6579 -a password -h 172.25.18.234`



## RabbitMQ

常用操作

```bash
rabbitmqctl help
rabbitmqctl list_users
rabbitmqctl list_vhosts
rabbitmqctl list_queues
rabbitmqctl add_user zhangsan
rabbitmqctl set_user_tags zhangsan administrator
rabbitmqctl set_permissions -p / zhangsan ".*" ".*" ".*"
rabbitmq-plugins list #显示插件列表
rabbitmq-plugins enable rabbitmq_management #打开插件（web管理页面）
rabbitmq-plugins enable rabbitmq_management_agent

rabbitmqctl stop_app
rabbitmqctl join_cluster --ram rabbit@rabbit1           # 以RAM节点形式加入Rabbitmq集群
rabbitmqctl start_app
rabbitmqctl set_policy HA '^(?!amq\.).*' '{"ha-mode": "all"}'
rabbitmqctl list_policies
rabbitmqctl cluster_status
```

使用rabbitmqctl连接、管理远程rabbitmq cluster

1. 确保 /var/lib/rabbitmq/.erlang.cookie 内容一致
2. 连接时确保rabbitmq服务器名称一致，集群名称可通过 rabbitmqctl set_cluster_name xxx 设置

通过rabbitmq的15672管理端口获取rabbitmq信息（RESTful API）

```bash
curl -s -u openstack:password http://$(kubectl get svc cell002-rabbit1 -o jsonpath='{.spec.clusterIP}'):15672/api/nodes | jq '. | length'
```



## influxdb

客户端程序influx
```bash
show databases                                              # 显示数据库
create database <dbname>                                    # 创建数据库
drop database <dbname>                                      # 删除数据库
use k8s                                                     # 使用某个数据库
show measurements                                           # 显示度量（表）
# 注意，当measurements中有‘/’时，可以在measurements加上""，escape掉‘/’

select * from uptime limit 1                                # 显示表uptime中一条记录的所有列信息
select value from uptime limit 1                            # 显示表uptime中一条记录的value列信息
insert <tbname>,<tag[tags]> <value[values]> [timestamp]     # timestamp是主键
drop measurement <tbname>                                   # 删除表
SELECT value FROM "memory/node_utilization" WHERE "host_id" = '172.25.16.226' AND "type" = 'node' AND time > now() - 1h
SELECT value FROM "cpu/node_utilization" WHERE "host_id" = '172.25.16.226' AND "type" = 'node' AND time > now() - 1h
SELECT mean("value") FROM "network/rx_rate" WHERE "host_id" = '172.25.16.226' AND time > now() - 1h GROUP BY time(1m) fill(null)
SELECT mean("value") FROM "cpu/usage_rate" WHERE "type" = 'pod_container' AND time > now() - 1h GROUP BY time(1m), "container_name"
SELECT pod_name,max("value") as "runtime" FROM "uptime" WHERE "host_id" = '172.25.16.226' AND  "type" = 'pod_container' AND time > now() - 120s and time < now() GROUP BY "container_name"
SELECT mean("value") FROM "memory/usage" WHERE "type" = 'pod_container' AND time > now() - 1h GROUP BY time(2s), "container_name" fill(null)
```



## Prometheus



RESTful接口查询示例

```bash
# node-exporter:  rate(node_network_receive_bytes_total[1m])
#                 rate(node_network_transmit_bytes_total[1m])
# cAdvisor:       rate(container_network_transmit_bytes_total[1m])
#                 rate(container_network_receive_bytes_total[1m])

# 使用url-encode
curl -s "os-prometheus.prometheus-monitoring.svc:9090/api/v1/query_range?query=sum(rate(container_network_receive_bytes_total%7Bnode%3D~%22%5E.*%24%22%7D%5B1m%5D))&start=$(date +%s)&end=$(date +%s)&step=15" | jq

curl -s "os-prometheus.prometheus-monitoring.svc:9090/api/v1/query_range?query=sum(rate(container_network_receive_bytes_total%5B1m%5D))&start=$(date +%s)&end=$(date +%s)&step=15" | jq

curl -s "os-prometheus.prometheus-monitoring.svc:9090/api/v1/query?query=sum(rate(container_network_receive_bytes_total%7Bnode%3D~%22%5E.*%24%22%7D%5B1m%5D))" | jq

curl -s "os-prometheus.prometheus-monitoring.svc:9090/api/v1/query?query=(sum(rate(container_network_transmit_bytes_total%5B1m%5D))by(node))" | jq
curl -s "os-prometheus.prometheus-monitoring.svc:9090/api/v1/query?query=(sum(rate(container_network_receive_bytes_total%5B1m%5D))by(node))" | jq

curl -s "os-prometheus.prometheus-monitoring.svc:9090/api/v1/query?query=(sum(rate(node_network_transmit_bytes_total%5B1m%5D))by(instance))" | jq
curl -s "os-prometheus.prometheus-monitoring.svc:9090/api/v1/query?query=(sum(rate(node_network_receive_bytes_total%5B1m%5D))by(instance))" | jq

curl -s "os-prometheus.prometheus-monitoring.svc:9090/api/v1/query?query=sum(rate(container_network_transmit_bytes_total%7Bnode%3D%22platform-172%22%7D%5B1m%5D))" | jq
```



## Weavescope

RESTful API示例

```bash
curl -s os-weavescope-svc.default.svc/api/topology
/swarm-services
/ecs-tasks
/ecs-services
/processes
/processes-by-name
/pods
/services
/kube-controllers
/hosts
/weave
/containers
/containers-by-image
/containers-by-hostname
```





## Ceph



## KVM

### virsh操作

```bash
virsh list --all        # 找到没开机的虚拟机
virsh start <vmName>    # 启动虚机
virsh nodeinfo          # 宿主机节点信息
```



## drbd
### drbd常见命令

```bash
drbdadm create-md --force r0002 # 初始化
drbdadm up r0               # 启动车辆
drbdadm status r0           # 检查车辆状态
drbdadm primary r0 --force  # 强制发车
drbdadm sh-dev r0           # 查看resource对应的disk device
drbdadm dump r0
drbdadm secondary r0
drbdadm disconnect r0000    # 下车
drbdadm connect r0000       # 上车
drbdadm down r0000          # 弃车
drbdadm sh-resources        # 查看所有resources
drbdadm sh-ll-dev r0001     # 查看drbd资源的底层storage disk
drbdsetup r0002 show        #
```

### 修复处于Diskless状态的节点

~~~bash
ansible all -m shell -a "drbdadm status r0000"
master01 | SUCCESS | rc=0 >>
r0000 role:Secondary
  disk:Diskless client:no
  master02 role:Secondary
    peer-disk:UpToDate
  master03 role:Primary
    peer-disk:UpToDate

master03 | SUCCESS | rc=0 >>
r0000 role:Primary
  disk:UpToDate
  master01 role:Secondary
    peer-disk:Diskless peer-client:no
  master02 role:Secondary
    peer-disk:UpToDate

master02 | SUCCESS | rc=0 >>
r0000 role:Secondary
  disk:UpToDate
  master01 role:Secondary
    peer-disk:Diskless peer-client:no
  master03 role:Primary
    peer-disk:UpToDate
~~~


### 修复脑裂/standalone状态的节点

当出现脑裂（Split Brain）时，内核日志会有：<br>
`kernel: block drbd1: Split-Brain detected but unresolved, dropping connection!`

~~~bash
# 故障节点上执行：
drbdadm disconnect r0002
drbdadm connect --discard-my-data r0002
# 主节点上执行：
drbdadm disconnect r0002
drbdadm connect r0002
~~~

### 修复Inconsistent/Inconsistent状态

当节点处于`Inconsistent/Inconsistent`状态时，若遇到无法设置`Primary`主节点，执行如下操作修复

~~~bash
# 选取一个“主节点”，并在上面执行如下命令
drbdadm -- --overwrite-data-of-peer primary r0001
~~~

### 肉搏操作drbd存储

~~~bash
drbdadm secondary r0018
ansible controller -m shell -a "drbdadm down r0018"

@all lvremove centos/r0018
y

@all lvcreate --name r0018 --size 1g centos
y

@all drbdadm create-md --force r0018

ansible controller -m shell -a "drbdadm up r0018"
drbdadm primary --force r0018
blkid -o udev /dev/drbd18
~~~

### drbd周边知识

#### 块设备操作命令

~~~bash
blktrace
btrace
blkid   # 获取块设备的uuid、文件系统类型等信息
blkid -o udev /dev/drbd2  # 以udev格式化输出块设备信息
lsblk
fdisk -s /dev/sdb   # 获取块设备大小
fuser
df -h . # 查看当前文件系统存储空间的使用情况
~~~

#### 如何判断块设备是否在被使用中

- 带`O_EXCL`标志的去`open`块设备，如果打开成功，表明其它人未再使用该设备。
- 执行`fuser -vam /dev/mapper/* 2>&1`再次检查，以防万一
- A drive can appear in `/proc/mounts`
- A drive can be used as swap (use `/proc/swaps`)
- A drive can be part of an active LVM pv (use `pvdisplay`)
- A drive can be part of a dm-mapper RAID group (use `/proc/mdstat`)
- A drive can be directly accessed by an application (e.g. Oracle supports writing directly to a drive or partition instead of a filesystem) (use `fuser`)
- A drive can be directly accessed by a virtual machine (use `fuser`)
- A drive can be referenced by a loopback device (e.g: `mount /dev/sda -o offset=1M /foo`) (use `losetup -a`)

#### debugfs

debugfs是linux用于内核debug的有力工具，默认挂载路径`/sys/kernel/debug`。<br>
drbd内核模块使用debugfs，路径为`/sys/kernel/debug/drbd/`



## ansible

常用操作：
```bash
ansible all -m shell -a 'docker rmi nginx:1.0'
ansible all -m ping
ansible all -m ping -vvvv    #  常用于定位问题
ansible all -m copy -a ''
ansible all -m copy -a  "src=${SRC_PATH} dest=${SRC_PATH} mode=755"
ansible all -m service ''
ansible -B 315360000 -P 0 all -m shell -a "hehe >> xixi.log &"  # 要使用ansible执行后台命令，必须使用background方式，且poll时间设为0
salt的配置文件在/etc/salt/xxxxx TODO
ansible all -m shell -a 'docker rmi nginx:1.0'
ansible all -m ping   # ping所有node    功能等同于salt '*' test.ping
ansible controller --list-hosts | grep -v hosts
ansible all -i 10.125.31.182, -m ping
```
向ansible的hosts中增加节点，以管理该节点

```bash
echo ${node_ip} >> /etc/ansible/hosts
ansible $node_ip -m ping
if [ $? -ne 0 ];then
    sed -i '$d' /etc/ansible/hosts
    log_err "${node_ip} is not controlled by ansible"
fi
```
通过ansible远程执行脚本，并获取返回值：

```bash
ansible_result=$(ansible $node_ip -m script -a '/path/to/shell.sh')
if [ $? -ne 0 ];then
    sed -i '$d' /etc/ansible/hosts
    log_err "ansible result of ${node_ip}: ${ansible_result}"
fi
```
更新ansible的hosts

```bash
echo -e "[${node_type}]\n${node_ip}" >> /etc/ansible/hosts
ansible all -m copy -a 'src=/etc/ansible/hosts dest=/etc/ansible/'
```
远程复制文件

    ansible $node_ip -m copy -a "src=${CURR_DIR}/worker dest=/root/"

## YAML

使用`yml2json`完成转换，安装方式为`pip install yml2json`。



## JSON

### JSON Patch

JSON PATCH定义修改json文件内容的数据格式，其避免了修改过程中传输整个json文件的问题，而只需传输待修改的部分。
同HTTP的PATCH方法结合使用，能通过RESTful API更新文件（资源）的部分内容。

JSON Patch在[RFC 6902](https://tools.ietf.org/html/rfc6902)中定义。

#### 简单示例
原始文件

```bash
{
  "baz": "qux",
  "foo": "bar"
}
```
一些列patch操作

```bash
[
  { "op": "replace", "path": "/baz", "value": "boo" },
  { "op": "add", "path": "/hello", "value": ["world"] },
  { "op": "remove", "path": "/foo" }
]
```
结果

```bash
{
  "baz": "boo",
  "hello": ["world"]
}
```

#### 实用例子

整体替换/覆盖pod的标签：
```bash
curl -H "Content-Type:application/json-patch+json" --request PATCH "http://127.0.0.1:8888/api/v1/namespaces/default/pods/milk-rc-qlzst" -d "[{ \"op\": \"add\",\"path\":\"/metadata/labels\",\"value\":{\"app2\":\"milk2\", \"app\":\"milk\"}}]"
```

为pod增加`role=master`的标签：
```bash
curl -H "Content-Type:application/json-patch+json" --request PATCH "http://127.0.0.1:8888/api/v1/namespaces/default/pods/wechat-core-rc-8cthk" -d "[{ \"op\": \"add\",\"path\":\"/metadata/labels/role\",\"value\":\"master\"}]"
```

删除pod的`role`标签：
```bash
curl -H "Content-Type:application/json-patch+json" --request PATCH "http://127.0.0.1:8888/api/v1/namespaces/default/pods/wechat-core-rc-8cthk" -d "[{ \"op\": \"remove\",\"path\":\"/metadata/labels/role\"}]"
```

#### 操作说明
**Add**

> `{ "op": "add", "path": "/biscuits/1", "value": { "name": "Ginger Nut" } }`<br>
> Adds a value to an object or inserts it into an array. In the case of an array, the value is inserted before the given index. The - character can be used instead of an index to insert at the end of an array.

**Remove**

> `{ "op": "remove", "path": "/biscuits" }`<br>
> Removes a value from an object or array.<br>
> `{ "op": "remove", "path": "/biscuits/0" }`<br>
> Removes the first element of the array at biscuits (or just removes the “0” key if biscuits is an object)

**Replace**

> `{ "op": "replace", "path": "/biscuits/0/name", "value": "Chocolate Digestive" }`<br>
> Replaces a value. Equivalent to a “remove” followed by an “add”.

**Copy**

> `{ "op": "copy", "from": "/biscuits/0", "path": "/best_biscuit" }`<br>
> Copies a value from one location to another within the JSON document. Both from and path are JSON Pointers.

**Move**

> `{ "op": "move", "from": "/biscuits", "path": "/cookies" }`<br>
> Moves a value from one location to the other. Both from and path are JSON Pointers.

**Test**

> `{ "op": "test", "path": "/best_biscuit/name", "value": "Choco Leibniz" }`<br>
> Tests that the specified value is set in the document. If the test fails, then the patch as a whole should not apply.

参见[jsonpatch](http://jsonpatch.com)。

### 常用操作

使用jq格式化输出

```bash
jq .
kubectl get pod --all-namespaces -o json | jq -r '.items[] | select(.spec.hostNetwork) | .metadata.namespace + ":" +.metadata.name' | wc -l
kubectl get pods -o json | jq '.items[] | select(.spec.hostname == "webapp-server-2" or .spec.hostname == "webapp-server-1") | .metadata.name' | tr -d '"'
kubectl get pods -o json | jq '.items[].metadata.name'
kubectl get pod mha-manager-s647h -o json | jq 'del(.spec)'     # 不输出.spec
kubectl get ns "$0" -o json | jq "del(.spec.finalizers[0])">"tmp.json"
kubectl get pods -o json | jq '.items[] | select(.spec.schedulerName == "my-scheduler") | select(.spec.nodeName == null) | .metadata.name' | tr -d '"'
kubectl get pods -o json | jq '.items[] | select(.metadata.labels.node == "mysql-node1") | .status.hostIP'
kubectl get pods -o json | jq '.items[] | select(.metadata.name | startswith("mysql")) | .status.hostIP'   # 通配、wildcard
kubectl get pods -o json | jq '.items[] | select(.metadata.name | startswith("mysql")) | .metadata.labels.node + " " + .status.hostIP'  # 多个域在一行同时输出
kubectl get node zy-os-okd-m -o json | jq '.status.addresses[] | select(.type == "InternalIP") | .address' | tr -d '"' # 获取kubernetes节点集群IP地址
kubectl get node -l node=node1 -o json | jq '.items[0].status.addresses[] | select(.type == "InternalIP") | .address' | tr -d '"'
echo '{ "app": "rabbitmq-cluster", "node": "rabbit3" }' | jq 'to_entries[]'
docker info -f '{{json .DriverStatus}}' | jq '.[] | .[0] + " " + .[1]'
jq '.items | length'
jq ".items[] | select(.metadata.name == \"${n}\") | .spec.clusterIP"
${KUBECTL} get node -o json|jq -r .items|jq -r length
cat xxx | jq .mysql[0].node -r # -r去掉""
jq -c
kubectl get pod milk-rc-fc9m7 -o json | jq -r '.metadata.labels | to_entries[] | select(.key != "role") | .key + "=" + .value'
```

将 `{ "app": "rabbitmq-cluster", "node": "rabbit3" }` 格式转换为 `app=rabbitmq-cluster,node=rabbit3`

```bash
selectors=$(echo $selectors | jq 'to_entries[]| .key + "=" + .value' | tr -d '"')
selectors=$(echo $selectors | sed 's/ /,/g')
```





## base64

一种编码方式，主要将数据字符串化，便于传递、避免特殊字符带来的问题。

```bash
# 编码 encode
[zy@m1 ~]$ echo -n "admin" | base64
YWRtaW4=

# 解码 decode
[zy@m1 ~]$ echo YWRtaW4= | base64 -d
admin
```



## Shell脚本

### Bash实例

#### 循环

```bash
for i in $(seq 1 431); do rm -f mysql-bin.$(printf "%06d" $i); done
for ((i=${hehe}; i<${hehe}+4; i++)); do printf "%03d\n" $i; done   #按照指定位数，左补零
for ((i=1; i<4; i++)); do echo $i; done
count=0;while true; do let 'count++'; echo ${count}; done
```

#### 获取入参名称及值

通过`indirect variables`实现。

示例1：

```bash
function test()
{
    echo $1 ${!1}
}

xixi=hehe
test xixi
```

示例2：

```bash
# indirect variables
declare -a GET_1_PER_MIN=("hehe" "xixi")

function start_task()
{
    tmp="${1}[@]"
    echo $1
    for val in "${!tmp}"; do
        echo ${val}
    done
}

start_task GET_1_PER_MIN
```

#### 字符串转array和array切片

示例1：

```bash
hehe="111 222 333 444 -xx dsaff"
function test()
{
    tmp=($@)
    xixi=${tmp[@]:2}
    echo $xixi
}
test $hehe
```

示例2：

```bash
MYSQL_PODS=$($KUBECTL $SERVER get pod -o wide | grep $MYSQL_POD_NAME | awk '{print $1,$6}')
IFS=' ' read -r -a MYSQL_PODS <<< $MYSQL_PODS
```

#### trap

trap recovery RETURN



#### 字符串切片

```bash
${var:offset:number}   #字符串切片
${var: -length}        #字符串切片
```



#### 截取字符串子串

```bash
pids=1020/java
pids=${pids%/*}
etcdip_str=${etcdip_str%,}  #截取尾部的,

items=1,2,3,4, ; echo $items; items=${items%,}; echo $items #如果最后一个字符是','，则去掉
hehe=cell001;echo ${hehe:(4)};echo ${hehe:(-3)} # 字符串切片
hehe=cell001; echo ${hehe:0:4}
cell
hehe=cell001; echo ${hehe:4}
001
hehe=cell001; echo ${hehe:-3}
cell001
hehe=cell001; echo ${hehe:(-3)}
001
```



#### 字符串比较

建议加上双引号""，否则当$1为空时会报错。

```bash
function compare()
{
    if [ "$1" = "hehe" ]; then
        log_info "file $1 exists"
    else
        log_err "file $1 not exists"
        exit 1
    fi
}
```



#### 计算数组中元素个数

```bash
NODES=($(kubectl --server $SERVER get nodes -o json | jq '.items[].metadata.name' | tr -d '"'))
NUMNODES=${#NODES[@]}
```



#### 当没有stress时如何对CPU施压

```bash
timeout 600s bash -c "while true; do echo 1 > /dev/null; done" &
timeout 600s bash -c "while true; do echo 1 > /dev/null; done" &
...
timeout 600s bash -c "while true; do echo 1 > /dev/null; done" &

kill $(jobs -p)
```



#### 并发执行多任务

```bash
( os::build::image "${tag_prefix}-pod"                     images/pod ) &
( os::build::image "${tag_prefix}-template-service-broker" images/template-service-broker ) &

for i in `jobs -p`; do wait $i; done
```



#### 替换变量

```bash
set -- "$@" --init-file="$tempSqlFile"
```



#### 日志输出：

```bash
function log_print()
{
    echo $(date +"%Y-%m-%d %T") $1 >> ${LOG_FILE}
}

function log_info()
{
    log_print "INF: $1"
}

log_info "hehe"
```



#### 检查文件是否存在
```bash
function check_file()
{
    if [ -f "$1" ]; then
        log_info "file $1 exists"
    else
        log_err "file $1 not exists"
        exit 1
    fi
}
```



#### IFS指定分隔符
```bash
CLUSTER_NODES=cell001-mysql-node1,cell001-mysql-node2,cell001-mysql-node3
OLD_IFS="$IFS"
IFS=","
nodes=(${CLUSTER_NODES})
IFS="${OLD_IFS}"
for n in ${nodes[@]}; do xxx; done
```



#### 遍历处理被IFS分隔过的数组
```bash
IFS=' ' read -r -a BACKENDS <<< $BACKENDS
for ((i=0; i<${#BACKENDS[@]}; i+=2))
do
    be_name=${BACKENDS[i]}
    be_addr=${BACKENDS[i+1]}
    log_dbg "trying to clockdiff with backend ${be_name}(${be_addr}) ..."
    clockdiff ${be_addr} > ${RESULT_DIR}/${be_name}
    if [ $? == 0 ]; then
        log_dbg "result: $(cat ${RESULT_DIR}/${be_name})"
    else
        log_err "clockdiff with backend ${be_name}(${be_addr}) failed"
    fi
done
```



#### 从文件中读取信息
```bash
function proc_rc_with_multi_replicas()
{
    cat $1 | sed '/^#.*\|^$/d' | while read line
    do
        log_dbg $line
    done
}
```



#### 比较两个变量是否相同
```bash
if [ ${temp} = ${rc} ]; hen
    log_err "rc has been processed, need bypassing it: ${rc}"
    return 1
fi
```



#### 高级test语句: 正则表达式，判断是否为纯数字
```bash
if (! [[ ${migrate_threshold} =~ ^[0-9]+$ ]]) && (! [[ ${migrate_threshold} =~ [xX] ]]); then
    log_err "invalid rule, migrate_threshold(${migrate_threshold})"
    return 1
fi
if ! [[ ${pod_anti_affinity_required} =~ [nNyY] ]]; then
    log_err "invalid rule, pod_anti_affinity_required(${pod_anti_affinity_required})"
    return 1
fi

if [ $# -ne 2 ] && [ $# -ne 3 ]; then
    echo "Usage: $0 <node_ip> <node_type> [node_idx]" > /dev/stdout
    exit 1
fi

case ${node_type} in
    clusCtrl | moniClus | appsCtrl | compClus | cellClus)
        echo "correct nodeType ${node_type}";;
    *)
        log_err "Invalid node_type ${node_type}";;
esac
```



#### 判断一个文件夹是否为空
~~~
if [ -z "$(ls -A /path/to/dir)" ]; then
   echo "Empty"
else
   echo "Not Empty"
fi
~~~



#### 使用cat生成文件

```bash
cat <<EOF >/usr/lib/systemd/system/kube-flanneld.service
xxxxxxx
xxxxxxxx
EOF
```



#### 运算

```bash
cell_num=997; tmp=$[ ( ${cell_num} - 1 ) % 3 ]; echo $tmp
```



### 其它记录

使用kill发送信号采用如下方式：

```bash
kill -s HUP $(pidof dnsmasq)    # 脚本中执行 kill -SIGHUP $(pidof dnsmasq) 会报错
```



## Java

### Debug Java

```bash
jps
jstack
jstack -l pid   #用于查看线程是否存在死锁
jstat -gc [pid]   #查看gc情况
jstat -gcnew [pid] #查看young区的内存使用情况，包括MTT（最大交互次数就被交换到old区），TT是目前已经交换的次数
jstat -gcold    #查看old区的内存使用情况
```





## Python

### 使用pip

```bash
yum install python-pip
pip --version
pip install xxx
pip uninstall xxx
pip search "xxx"
pip list
pip list --outdated

# 使用指定的pip源
mkdir -p /root/.pip/
cat <<EOF >/root/.pip/pip.conf
[global]
index-url = http://10.153.3.130/pypi/web/simple
trusted-host = 10.153.3.130
EOF
```

### 实例

#### 字符串操作

```python
images = images.replace(' ', ':').split('\\n')  # 替换字符和将字符串分割为array
idx = image.find(':9999/') + 6                  # 查找子字符串
alias = image[idx:]                             # 截取字符串
```



## 正则表达式Regex





# Memo and Skills



## 宿主机上直接修改容器内文件

宿主机上`/proc/{pid}/cwd`是pid所在进程当前的工作路径，如果pid是容器中业务进程在宿主机上的进程号，那么cwd文件夹中能直接看到容器中“当前工作目录”。
因此，宿主机上直接修改cwd文件夹中的内容，也能在容器中生效。



## vi/vim

### 常用操作

```bash
# 全局字符串替换
%s/xxx/yyy/g
# up half page
Ctrl + U
# up
Ctrl + B
# down half page
Ctrl + D
# down
Ctrl + F
```





## 奇技淫巧

在Office Word中打钩：

```
alt + 9745
```
