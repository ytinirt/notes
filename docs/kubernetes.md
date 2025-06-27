# TOC

<!-- TOC -->
* [TOC](#toc)
* [集群控制面高可用方案](#集群控制面高可用方案)
* [多实例leader选举](#多实例leader选举)
* [Pod健康和就绪检查遇到的坑](#pod健康和就绪检查遇到的坑)
  * [问题描述](#问题描述)
  * [结论](#结论)
  * [分析](#分析)
  * [其它](#其它)
* [Kubernetes高级调度特性](#kubernetes高级调度特性)
  * [亲和性](#亲和性)
    * [配置示例](#配置示例)
  * [自定义调度器](#自定义调度器)
* [API优先级APIPriorityAndFairness](#api优先级apipriorityandfairness)
* [以CRD方式扩展API](#以crd方式扩展api)
* [Pod调度如何感知volume的topology](#pod调度如何感知volume的topology)
* [CPU资源高级管理](#cpu资源高级管理)
* [kube-proxy集群内负载均衡](#kube-proxy集群内负载均衡)
  * [深入iptables模式的kube-proxy](#深入iptables模式的kube-proxy)
    * [实现会话亲和性](#实现会话亲和性)
* [域名解析和DNS策略](#域名解析和dns策略)
  * [Pod's DNS Policy](#pods-dns-policy)
* [对象名称和字符串格式检查](#对象名称和字符串格式检查)
* [kubectl插件](#kubectl插件)
* [认证Authentication](#认证authentication)
  * [账号](#账号)
    * [Kubernetes用户](#kubernetes用户)
      * [服务账号Service Account](#服务账号service-account)
      * [证书用户User](#证书用户user)
        * [如何创建一个证书用户](#如何创建一个证书用户)
    * [通过webhook对接外部认证提供商](#通过webhook对接外部认证提供商)
  * [到达聚合apiserver的请求中如何携带用户信息](#到达聚合apiserver的请求中如何携带用户信息)
  * [TODO](#todo)
* [鉴权Authorization](#鉴权authorization)
  * [判断我是否有权限](#判断我是否有权限)
  * [判断谁有权限操作](#判断谁有权限操作)
  * [常见操作](#常见操作)
* [安全](#安全)
  * [Pod Security Admission](#pod-security-admission)
  * [配置container Capabilities](#配置container-capabilities)
  * [Kubernetes对接容器安全](#kubernetes对接容器安全)
    * [CRI接口中LinuxContainerSecurityContext](#cri接口中linuxcontainersecuritycontext)
    * [OCI接口中LinuxDeviceCgroup](#oci接口中linuxdevicecgroup)
* [操作实例](#操作实例)
  * [大规模集群实践](#大规模集群实践)
    * [社区优化跟踪](#社区优化跟踪)
  * [在大规模集群中优雅的操作](#在大规模集群中优雅的操作)
    * [集群Pod总数](#集群pod总数)
    * [集群Event总数](#集群event总数)
    * [筛选慢操作list all](#筛选慢操作list-all)
    * [筛选出最早创建的一组pod（用于onDelete策略的更新）](#筛选出最早创建的一组pod用于ondelete策略的更新)
  * [节点维护](#节点维护)
  * [便捷操作](#便捷操作)
  * [event使用独立的etcd集群](#event使用独立的etcd集群)
  * [模拟list对kube-apiserver进行压测](#模拟list对kube-apiserver进行压测)
  * [获取openapi json](#获取openapi-json)
  * [从secret中获取证书信息](#从secret中获取证书信息)
  * [从KubeConfig文件中提取证书秘钥](#从kubeconfig文件中提取证书秘钥)
  * [堆栈文件分析](#堆栈文件分析)
  * [根据sa生成kubeconfig](#根据sa生成kubeconfig)
  * [kubeconfig跳过服务端证书校验](#kubeconfig跳过服务端证书校验)
  * [定制kubectl输出](#定制kubectl输出)
  * [kubectl patch操作](#kubectl-patch操作)
  * [常见操作](#常见操作-1)
  * [资源遍历](#资源遍历)
    * [遍历列出所有的资源类型及支持的操作](#遍历列出所有的资源类型及支持的操作)
    * [遍历所有pod](#遍历所有pod)
    * [遍历所有pod及其容器](#遍历所有pod及其容器)
    * [遍历所有工作负载](#遍历所有工作负载)
    * [遍历一个命名空间下所有资源](#遍历一个命名空间下所有资源)
    * [遍历一个命名空间下所有资源的label和annotations](#遍历一个命名空间下所有资源的label和annotations)
    * [遍历所有区分命名空间的资源的内容](#遍历所有区分命名空间的资源的内容)
    * [遍历所有跨命名空间的资源](#遍历所有跨命名空间的资源)
    * [遍历所有跨命名空间的资源的label和annotations](#遍历所有跨命名空间的资源的label和annotations)
    * [遍历所有跨命名空间的资源的内容](#遍历所有跨命名空间的资源的内容)
    * [遍历所有pod的cpu request配置](#遍历所有pod的cpu-request配置)
  * [客户端访问集群时context配置](#客户端访问集群时context配置)
  * [ConfigMap使用](#configmap使用)
  * [日志相关配置](#日志相关配置)
  * [提升集群HA性能](#提升集群ha性能)
  * [强制删除Pod](#强制删除pod)
  * [Pod中获取PodIP的方法](#pod中获取podip的方法)
  * [emptyDir在宿主机上的路径](#emptydir在宿主机上的路径)
    * [节点上emptyDir用量统计](#节点上emptydir用量统计)
    * [远程到节点统计emptyDir用量](#远程到节点统计emptydir用量)
  * [FC存储多路径的PV配置](#fc存储多路径的pv配置)
  * [编译kubelet](#编译kubelet)
  * [获取k8s控制面组件指标](#获取k8s控制面组件指标)
  * [kubeadm部署的集群的操作](#kubeadm部署的集群的操作)
  * [kube-apiserver内部本地访问客户端](#kube-apiserver内部本地访问客户端)
  * [读取 kubelet_internal_checkpoint](#读取-kubeletinternalcheckpoint)
* [最佳实践](#最佳实践)
  * [使用finalizers拦截资源删除](#使用finalizers拦截资源删除)
    * [手动清理finalizers](#手动清理finalizers)
  * [资源限制](#资源限制)
    * [容器进程数限制pids](#容器进程数限制pids)
  * [HPA](#hpa)
  * [集群内通过svc访问外部服务](#集群内通过svc访问外部服务)
* [性能调优](#性能调优)
  * [读懂监控指标](#读懂监控指标)
    * [etcd监控指标](#etcd监控指标)
    * [kube-apiserver监控指标](#kube-apiserver监控指标)
    * [kube-controller-manager监控指标](#kube-controller-manager监控指标)
    * [kube-scheduler监控指标](#kube-scheduler监控指标)
    * [kubelet监控指标](#kubelet监控指标)
  * [内存优化](#内存优化)
  * [查看defaultCpuSet核上CPU使用量](#查看defaultcpuset核上cpu使用量)
* [Deep Dive系列](#deep-dive系列)
  * [kube-apiserver](#kube-apiserver)
    * [服务启动流程](#服务启动流程)
    * [服务端fieldSelector](#服务端fieldselector)
    * [REST Storage](#rest-storage)
    * [安装API及其REST Storage](#安装api及其rest-storage)
    * [API定义和版本](#api定义和版本)
    * [序列化和反序列化](#序列化和反序列化)
      * [TypeMeta的反序列化](#typemeta的反序列化)
      * [外部版本的序列化和反序列化](#外部版本的序列化和反序列化)
      * [codec和codec factory](#codec和codec-factory)
    * [资源schema](#资源schema)
    * [健康检查/healthz](#健康检查healthz)
    * [就绪检查/readyz](#就绪检查readyz)
    * [node authorizer实现](#node-authorizer实现)
  * [kube-controller-manager](#kube-controller-manager)
    * [配置和初始化](#配置和初始化)
    * [leader选举](#leader选举)
    * [核心Controller](#核心controller)
  * [kube-scheduler](#kube-scheduler)
    * [配置和初始化](#配置和初始化-1)
    * [leader选举](#leader选举-1)
    * [资源调度](#资源调度)
  * [kubelet](#kubelet)
    * [配置和初始化](#配置和初始化-2)
    * [PLEG](#pleg)
    * [调用CRI接口](#调用cri接口)
    * [（间接）通过CNI接口管理网络](#间接通过cni接口管理网络)
    * [通过CSI管理存储](#通过csi管理存储)
    * [设备和资源管理](#设备和资源管理)
      * [资源计算和预留](#资源计算和预留)
        * [为容器进程设置oom_score_adj](#为容器进程设置oomscoreadj)
      * [Topology Manager](#topology-manager)
      * [CPU Manager](#cpu-manager)
        * [遍历所有Pod的cpuset配置](#遍历所有pod的cpuset配置)
      * [Memory Manager](#memory-manager)
      * [Device Manager](#device-manager)
    * [节点优雅关机 GracefulNodeShutdown](#节点优雅关机-gracefulnodeshutdown)
  * [库函数和实操](#库函数和实操)
    * [特性门featuregate](#特性门featuregate)
    * [处理runtime.Object](#处理runtimeobject)
      * [获取meta.Object信息](#获取metaobject信息)
* [Debug](#debug)
  * [kube-apiserver](#kube-apiserver-1)
  * [kubelet](#kubelet-1)
  * [kube-controller-manager](#kube-controller-manager-1)
  * [kube-scheduler](#kube-scheduler-1)
* [备忘](#备忘)
  * [k8s版本信息](#k8s版本信息)
  * [从源码编译kubernetes时版本信息](#从源码编译kubernetes时版本信息)
  * [修改结构体定义后更新api-rules校验](#修改结构体定义后更新api-rules校验)
  * [构建时如何选取version](#构建时如何选取version)
  * [StatefulSet无法更新中volumeClaimTemplates的request](#statefulset无法更新中volumeclaimtemplates的request)
  * [其它](#其它-1)
<!-- TOC -->

# 集群控制面高可用方案
TODO
kubernetes的组件，例如apiserver、controller、scheduler、kube-dns在配置时，均能指定多个server，使用failover方式保证高可用。
以apiserver为例，帮助信息中有：
```bash
--etcd-servers=[]: List of etcd servers to connect with (http://ip:port), comma separated.
```
通过--etcd-servers指定多个etcd服务器，apiserver能failover方式访问这些服务。

# 多实例leader选举
客户端代码路径：
k8s.io/kubernetes/pkg/client/leaderelection/leaderelection.go


# Pod健康和就绪检查遇到的坑

## 问题描述
Pod进行健康和就绪检查配置中，发现某些已有健康检查的服务，在增加就绪检查后Pod一直不就绪，且健康检查也出问题。如下健康检查为例
```bash
livenessProbe:
  httpGet:
    host: 127.0.0.1
    path: /
    port: 9311
  initialDelaySeconds: 600
  periodSeconds: 60
  timeoutSeconds: 30
```
Pod正常工作。再增加就绪检查：
```bash
readinessProbe:
  httpGet:
    host: 127.0.0.1
    path: /
    port: 9311
  initialDelaySeconds: 5
  periodSeconds: 30
  timeoutSeconds: 25
```
以后，Pod一直未能就绪，且因健康检查失败而反复重启。

## 结论

**检查方法httpGet在容器外执行，强烈建议不要指定host（除非知晓其中的风险）**
httpGet检查在容器外执行，但其行为表现严重受到host影响：
- 指定有host时，httpGet访问该host上的相应端口，若host指定为127.0.0.1，则访问节点本地的服务端口，外在表现为“容器外执行”
- 未指定host时，httpGet默认访问该Pod（Pod IP）上相应端口，在容器网络（例如flannel、kube-proxy）中该请求直接转发到容器中，外在表现是访问容器内部端口、在“容器内执行”。

**检查方法tcpSocket在容器外执行，但不支持指定host，请求直接转发到容器中**
tcpSocket检查无法指定host，直接同该Pod（Pod IP）上相应端口建立连接，该连接直接转发到容器中，因此外在表现是访问容器内部端口、在“容器内执行”。

**检查方法exec在容器内执行**
exec检查指定的操作在容器内执行。


## 分析

参见代码`kubernetes/kubernetes/pkg/kubelet/prober/prober.go`。

就着结论，我们来分析为什么会出现上述问题中的表现。

仅配置健康检查时，指定host为127.0.0.1，其实访问节点本地的9311端口。目前，大多数服务将容器内部端口通过nodePort方式暴露到节点上，且nodePort端口同容器内部端口保持一致，健康检查能通过如下流程顺利执行httpGet操作
> kubelet的Probe模块（容器外）发起HTTP请求 -> kube-proxy的nodePort -> 容器内targetPort ->容器内服务。

当加入就绪检查后情况发生变化。就绪检查中指定host为127.0.0.1，由于Pod还未就绪、Service没有可用的Endpoint，访问节点本地9311端口时失败，pod则一直不就绪。相应的，其健康检查也无法访问节点本地9311端口，导致健康检查失败、Pod反复重启。

解决办法在于去掉健康和就绪检查中的host配置，使httpGet请求发送到Pod内，不再依赖节点上nodePort暴露的服务。


## 其它
某些服务配置了host过滤，仅支持访问指定host，在健康和就绪检查的httpGet中增加如下配置即可：
```bash
httpGet:
  httpHeaders:
  - name: Host
    value: ${ALLOWED_HOST}
  path: /
  port: 9311
  scheme: HTTP
```
健康和就绪检查中增加HTTP扩展头部`Host: ${ALLOWED_HOST}`，其中`${ALLOWED_HOST}`是服务中配置的host过滤中允许访问的host。


# Kubernetes高级调度特性
为Pending状态的Pod选取一个 **合适** 的Node去运行，是Kubernetes调度的唯一目的。该目的简单、明确，但最重要也是最麻烦的在于 **“合适”** 两字。
除了默认调度器（`default kubernetes scheduler`），Kubernetes高级调度特性(`Advanced Scheduling`)引入了更加灵活的策略，以应对复杂多样的业务需求。

## 亲和性
设想有一个Pending状态等待调度的Pod，尝试用Kubernetes高级调度特性-亲和性，找到最优解时，需要考虑如下几方面的内容：
| 亲和对象 | 亲和类型 | 策略 | 运算符 |
| --- | --- | --- | --- |
| Node<br>Pod | 亲和(affinity)<br>反亲和(anti-affinity) | requiredDuringSchedulingIgnoredDuringExecution<br>requiredDuringSchedulingRequiredDuringExecution<br>preferredDuringSchedulingIgnoredDuringExecution | In/NotIn<br>Exists/DoesNotExists<br>Gt/Lt |

### 配置示例
当有worker时，优先调度到worker上，否则调度到master上：
```yaml
affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
      - matchExpressions:
        - key: node-role.kubernetes.io/worker
          operator: Exists
      - matchExpressions:
        - key: node-role.kubernetes.io/master
          operator: Exists
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        preference:
          matchExpressions:
          - key: node-role.kubernetes.io/worker
            operator: Exists
      - weight: 1
        preference:
          matchExpressions:
          - key: node-role.kubernetes.io/master
            operator: Exists
tolerations:
- effect: NoSchedule
  key: node-role.kubernetes.io/master
  operator: Exists
```

## 自定义调度器
custom scheduler，通过Bash脚本实现自定义调度器示例
```bash
#!/bin/bash
KUBECTL='xxx'
SERVER='xxx'
MYSQL_POD_NAME='mysql-node'

function find_mysql_master_node()
{
    MYSQL_PODS=$($KUBECTL --server $SERVER get pod -o wide | grep $MYSQL_POD_NAME | grep Running | awk '{print $6,$7}')
    IFS=' ' read -r -a MYSQL_PODS <<< $MYSQL_PODS
    for ((i=0;i<${#MYSQL_PODS[@]};i+=2));
    do
        podip=${MYSQL_PODS[i]}
        nodeip=${MYSQL_PODS[i+1]}
        result=$(mysql -uroot -ppassword -h${podip} --connect-timeout=5 -e 'show slave hosts;')
        if [ -n "$result" ]; then
            echo $nodeip
            return
        fi
    done
    echo null
    return
}
function find_k8s_master_node()
{
    NODES=$($KUBECTL --server $SERVER get node | grep -v NAME | awk '{print $1}')
    for i in ${NODES};
    do
        result=$(ssh root@${i} ps -ef | grep kube-controller | grep -v grep)
        if [ -n "$result" ]; then
            echo ${i}
            return
        fi
    done
    echo null
    return
}
while true;
do
    for POD in $($KUBECTL --server $SERVER get pod -o json | jq '.items[] | select(.spec.schedulerName == "smart-scheduler") |
            select(.spec.nodeName == null) | select(.status.phase == "Pending") | .metadata.name' | tr -d '"');
    do
        NODES=$($KUBECTL --server $SERVER get node | grep Ready | awk '{print $1}')
        MYSQL_MNODE=$(find_mysql_master_node)
        K8S_MNODE=$(find_k8s_master_node)
        for NODE in ${NODES};
        do
            if [ ${NODE} != ${MYSQL_MNODE} ]; then
                if [ ${NODE} != ${K8S_MNODE} ]; then
                    curl --header "Content-Type:application/json" \
                         --request POST \
                         --data '{"apiVersion":"v1", "kind": "Binding", "metadata": {"name": "'$POD'"},
                                  "target": {"apiVersion": "v1", "kind": "Node", "name": "'$NODE'"}}' \
                         http://$SERVER/api/v1/namespaces/default/pods/$POD/binding/ #1>/dev/null 2>&1
                    echo "Assigned ${POD} to ${NODE}, bypass mysql master ${MYSQL_MNODE} and k8s master ${K8S_MNODE}"
                fi
            fi
        done
    done
    #echo mysql $(find_mysql_master_node)
    #echo k8s $(find_k8s_master_node)
    sleep 2
done
```

要使用上述自定义调度器，工作负载配置`schedulerName: smart-scheduler`。
自定义调度器就是一个“controller”，不停的“reconcile”。


# API优先级APIPriorityAndFairness
```bash
# https://www.yisu.com/zixun/523074.html
kubectl get --raw /debug/api_priority_and_fairness/dump_priority_levels
```

# 以CRD方式扩展API
https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/

# Pod调度如何感知volume的topology
环境中有三个节点，类型为Controller：
```bash
[root@zy-m224 hehe]# kubectl get node -l nodeType=controller
NAME      STATUS    ROLES                  AGE       VERSION
zy-m224   Ready     compute,infra,master   1d        v1.11.0+d4cacc0
zy-s222   Ready     compute,infra,master   1d        v1.11.0+d4cacc0
zy-s223   Ready     compute,infra,master   1d        v1.11.0+d4cacc0
```

创建`storageclass`为ha-low的pvc，其存在两个副本：
```bash
[root@zy-m224 hehe]# kubectl get sc ha-low -o yaml --export
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  annotations:
    storage.alpha.openshift.io/access-mode: ReadWriteOnce
  creationTimestamp: null
  name: ha-low
  selfLink: /apis/storage.k8s.io/v1/storageclasses/ha-low
parameters:
  fstype: ext4
  replicas: "2"
  selector: beta.kubernetes.io/arch=amd64,beta.kubernetes.io/os=linux,nodeType=controller
provisioner: ctriple.cn/drbd
reclaimPolicy: Retain
volumeBindingMode: Immediate
```

自动部署的pv和底层存储被调度到`zy-m224`和`zy-s222`节点：
```bash
[root@zy-m224 hehe]# kubectl get pvc test-pvc
NAME       STATUS    VOLUME    CAPACITY   ACCESS MODES   STORAGECLASS   AGE
test-pvc   Bound     r0005     1Gi        RWO            ha-low         46m
[root@zy-m224 hehe]# kubectl get pv r0005
NAME      CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS    CLAIM              STORAGECLASS   REASON    AGE
r0005     1Gi        RWO            Retain           Bound     default/test-pvc   ha-low                   46m
[root@zy-m224 hehe]# ansible controller -m shell -a "lvs | grep r0005"
zy-s223 | FAILED | rc=1 >>
non-zero return code

zy-m224 | SUCCESS | rc=0 >>
  r0005       centos -wi-ao----   1.00g

zy-s222 | SUCCESS | rc=0 >>
  r0005       centos -wi-ao----   1.00g
```

让pod，使用该pvc后，反复删除、重启pod，发现该pod只会调度到`zy-m224`和`zy-s222`节点：
```bash
[root@zy-m224 hehe]# pod | grep wechat
default        wechat-874jj       1/1       Running     0  8m    10.242.0.142   zy-m224
```

修改rc/wechat，将其绑定到错误的节点`zy-s223`:
```bash
...
      hostname: wechat
      nodeSelector:
        node: node3
        nodeType: controller
...
```

删除pod后重新调度，一直处于`Pending`状态，并报`volume node affinity conflict`：
```bash
[root@zy-m224 scripts]# kubectl describe pod wechat-82z6q
...
Events:
  Type     Reason            Age               From               Message
  ----     ------            ----              ----               -------
  Warning  FailedScheduling  3m (x25 over 3m)  default-scheduler  0/4 nodes are available: 1 node(s) had volume node affinity conflict, 3 node(s) didn't match node selector.
```

来龙去脉大致如下：kube-scheduler调度pod时，检查其绑定的volume，顺着pvc->pv，发现pv有配置`nodeAffinity`：
```bash
apiVersion: v1
kind: PersistentVolume
metadata:
...
spec:
...
  nodeAffinity:
    required:
      nodeSelectorTerms:
      - matchExpressions:
        - key: kubernetes.io/hostname
          operator: In
          values:
          - zy-m224
          - zy-s222
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ha-low
status:
  phase: Bound
```

阅读更多：
- [VOLUME TOPOLOGY-AWARE SCHEDULING](https://stupefied-goodall-e282f7.netlify.com/contributors/design-proposals/storage/volume-topology-scheduling/)


# CPU资源高级管理
TODO
- https://docs.openshift.com/container-platform/3.11/scaling_performance/using_cpu_manager.html
- https://kubernetes.io/docs/tasks/administer-cluster/cpu-management-policies/

# kube-proxy集群内负载均衡
作为K8s集群内默认负载均衡解决方案，kube-proxy支持模式方式：
* [ipvs](https://kubernetes.io/blog/2018/07/09/ipvs-based-in-cluster-load-balancing-deep-dive/)，未来发展方向
* [iptables](https://kubernetes.io/docs/concepts/services-networking/service/)，默认方式
* [user-space](https://kubernetes.io/docs/concepts/services-networking/service/)，已逐渐被淘汰

## 深入iptables模式的kube-proxy

### 实现会话亲和性
开启会话亲和性，`sessionAffinity: ClientIP`时，iptables规则：
```bash
:KUBE-SEP-2ZNXFH2VOSGBPAVV - [0:0]
:KUBE-SEP-G2V5AWNNIXO6IYNV - [0:0]
:KUBE-SEP-SRB22U7BNHNW5WLR - [0:0]
:KUBE-SVC-TYE23RAXJNHAJ33G - [0:0]
-A KUBE-NODEPORTS -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m tcp --dport 13332 -j KUBE-MARK-MASQ
-A KUBE-NODEPORTS -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m tcp --dport 13332 -j KUBE-SVC-TYE23RAXJNHAJ33G
-A KUBE-SEP-2ZNXFH2VOSGBPAVV -s 10.244.1.31/32 -m comment --comment "space22pbugsd/yibao-b:yibao-b" -j KUBE-MARK-MASQ
-A KUBE-SEP-2ZNXFH2VOSGBPAVV -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m recent --set --name KUBE-SEP-2ZNXFH2VOSGBPAVV --mask 255.255.255.255 --rsource -m tcp -j DNAT --to-destination 10.244.1.31:13332
-A KUBE-SEP-G2V5AWNNIXO6IYNV -s 10.246.0.133/32 -m comment --comment "space22pbugsd/yibao-b:yibao-b" -j KUBE-MARK-MASQ
-A KUBE-SEP-G2V5AWNNIXO6IYNV -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m recent --set --name KUBE-SEP-G2V5AWNNIXO6IYNV --mask 255.255.255.255 --rsource -m tcp -j DNAT --to-destination 10.246.0.133:13332
-A KUBE-SEP-SRB22U7BNHNW5WLR -s 10.243.1.179/32 -m comment --comment "space22pbugsd/yibao-b:yibao-b" -j KUBE-MARK-MASQ
-A KUBE-SEP-SRB22U7BNHNW5WLR -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m recent --set --name KUBE-SEP-SRB22U7BNHNW5WLR --mask 255.255.255.255 --rsource -m tcp -j DNAT --to-destination 10.243.1.179:13332
-A KUBE-SERVICES ! -s 10.240.0.0/12 -d 10.100.218.244/32 -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b cluster IP" -m tcp --dport 13332 -j KUBE-MARK-MASQ
-A KUBE-SERVICES -d 10.100.218.244/32 -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b cluster IP" -m tcp --dport 13332 -j KUBE-SVC-TYE23RAXJNHAJ33G
-A KUBE-SVC-TYE23RAXJNHAJ33G -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m recent --rcheck --seconds 10800 --reap --name KUBE-SEP-SRB22U7BNHNW5WLR --mask 255.255.255.255 --rsource -j KUBE-SEP-SRB22U7BNHNW5WLR
-A KUBE-SVC-TYE23RAXJNHAJ33G -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m recent --rcheck --seconds 10800 --reap --name KUBE-SEP-2ZNXFH2VOSGBPAVV --mask 255.255.255.255 --rsource -j KUBE-SEP-2ZNXFH2VOSGBPAVV
-A KUBE-SVC-TYE23RAXJNHAJ33G -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m recent --rcheck --seconds 10800 --reap --name KUBE-SEP-G2V5AWNNIXO6IYNV --mask 255.255.255.255 --rsource -j KUBE-SEP-G2V5AWNNIXO6IYNV
-A KUBE-SVC-TYE23RAXJNHAJ33G -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m statistic --mode random --probability 0.33332999982 -j KUBE-SEP-SRB22U7BNHNW5WLR
-A KUBE-SVC-TYE23RAXJNHAJ33G -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m statistic --mode random --probability 0.50000000000 -j KUBE-SEP-2ZNXFH2VOSGBPAVV
-A KUBE-SVC-TYE23RAXJNHAJ33G -m comment --comment "space22pbugsd/yibao-b:yibao-b" -j KUBE-SEP-G2V5AWNNIXO6IYNV
```
通过`recent`模块实现会话亲和性。

关闭会话亲和性，`sessionAffinity: None`时，iptables规则：
```bash
:KUBE-SEP-2ZNXFH2VOSGBPAVV - [0:0]
:KUBE-SEP-G2V5AWNNIXO6IYNV - [0:0]
:KUBE-SEP-SRB22U7BNHNW5WLR - [0:0]
:KUBE-SVC-TYE23RAXJNHAJ33G - [0:0]
-A KUBE-NODEPORTS -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m tcp --dport 13332 -j KUBE-MARK-MASQ
-A KUBE-NODEPORTS -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m tcp --dport 13332 -j KUBE-SVC-TYE23RAXJNHAJ33G
-A KUBE-SEP-2ZNXFH2VOSGBPAVV -s 10.244.1.31/32 -m comment --comment "space22pbugsd/yibao-b:yibao-b" -j KUBE-MARK-MASQ
-A KUBE-SEP-2ZNXFH2VOSGBPAVV -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m tcp -j DNAT --to-destination 10.244.1.31:13332
-A KUBE-SEP-G2V5AWNNIXO6IYNV -s 10.246.0.133/32 -m comment --comment "space22pbugsd/yibao-b:yibao-b" -j KUBE-MARK-MASQ
-A KUBE-SEP-G2V5AWNNIXO6IYNV -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m tcp -j DNAT --to-destination 10.246.0.133:13332
-A KUBE-SEP-SRB22U7BNHNW5WLR -s 10.243.1.179/32 -m comment --comment "space22pbugsd/yibao-b:yibao-b" -j KUBE-MARK-MASQ
-A KUBE-SEP-SRB22U7BNHNW5WLR -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m tcp -j DNAT --to-destination 10.243.1.179:13332
-A KUBE-SERVICES ! -s 10.240.0.0/12 -d 10.100.218.244/32 -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b cluster IP" -m tcp --dport 13332 -j KUBE-MARK-MASQ
-A KUBE-SERVICES -d 10.100.218.244/32 -p tcp -m comment --comment "space22pbugsd/yibao-b:yibao-b cluster IP" -m tcp --dport 13332 -j KUBE-SVC-TYE23RAXJNHAJ33G
-A KUBE-SVC-TYE23RAXJNHAJ33G -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m statistic --mode random --probability 0.33332999982 -j KUBE-SEP-SRB22U7BNHNW5WLR
-A KUBE-SVC-TYE23RAXJNHAJ33G -m comment --comment "space22pbugsd/yibao-b:yibao-b" -m statistic --mode random --probability 0.50000000000 -j KUBE-SEP-2ZNXFH2VOSGBPAVV
-A KUBE-SVC-TYE23RAXJNHAJ33G -m comment --comment "space22pbugsd/yibao-b:yibao-b" -j KUBE-SEP-G2V5AWNNIXO6IYNV
```


# 域名解析和DNS策略

## Pod's DNS Policy
参见[Pod’s DNS Policy](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy)

# 对象名称和字符串格式检查
参见[Object Names and IDs](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/)，Kubernetes中绝大多数对象名称需符合[RFC 1123](https://tools.ietf.org/html/rfc1123)要求，具体的：
* contain no more than 253 characters
* contain only lowercase alphanumeric characters, ‘-’ or ‘.’
* start with an alphanumeric character
* end with an alphanumeric character

其对应正则表达式为
```bash
'[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*'
```

标签Label的key合法格式
> Valid label keys have two segments: an optional prefix and name, separated by a slash (/).
> The name segment is required and must be 63 characters or less, beginning and ending with an alphanumeric character ([a-z0-9A-Z]) with dashes (-), underscores (_), dots (.), and alphanumerics between.
> The prefix is optional. If specified, the prefix must be a DNS subdomain: a series of DNS labels separated by dots (.), not longer than 253 characters in total, followed by a slash (/).
> Valid label values must be 63 characters or less and must be empty or begin and end with an alphanumeric character ([a-z0-9A-Z]) with dashes (-), underscores (_), dots (.), and alphanumerics between.

标签Label的value合法格式
> Valid label values must be 63 characters or less and must be empty or begin and end with an alphanumeric character ([a-z0-9A-Z]) with dashes (-), underscores (_), dots (.), and alphanumerics between.

参见[Labels and Selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)

就文件名filename而言，参照[The POSIX portable file name character set](https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.2.0/com.ibm.zos.v2r2.bpxa400/bpxug469.htm)：
* Uppercase A to Z
* Lowercase a to z
* Numbers 0 to 9
* Period (.)
* Underscore (_)
* Hyphen (-)


更详细的检查，请参见`https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/core/validation/validation.go`。


# kubectl插件
摘自 [kubectl overview](https://kubernetes.io/docs/reference/kubectl/overview/)

只要在`PATH`路径下创建以`kubectl-`开头的可执行文件，即可被`kubectl`识别，并作为插件进行集成使用。如下以`kubectl whoami`为例说明。

首先，创建`/usr/local/bin/kubectl-whoami`文件，其内容如下：
```bash
#!/bin/bash

# this plugin makes use of the `kubectl config` command in order to output
# information about the current user, based on the currently selected context
kubectl config view --template='{{ range .contexts }}{{ if eq .name "'$(kubectl config current-context)'" }}Current user: {{ printf "%s\n" .context.user }}{{ end }}{{ end }}'
```

然后，将其设置为可执行：
```bash
# chmod a+x /usr/local/bin/kubectl-whoami
```

最后，检验：
```bash
[root@xxx ~]# kubectl plugin list
The following compatible plugins are available:

/usr/local/bin/kubectl-whoami
[root@xxx ~]# kubectl whoami
Current user: kubernetes-admin

```


# 认证Authentication
## 账号
### Kubernetes用户
#### 服务账号Service Account
#### 证书用户User
##### 如何创建一个证书用户
参见 [certificate-signing-requests](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#normal-user)

创建私钥和csr文件：
```bash
openssl genrsa -out john.key 2048
openssl req -new -key john.key -out john.csr
```
注意，在创建`john.csr`文件时会交互式的输入`CN`和`O`属性，其分别配置了用户名称user name和用户组group。

创建K8s资源CertificateSigningRequest：
```bash
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: john
spec:
  groups:
  - system:authenticated
  request: xxxxxx
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
EOF
```
注意，其中`usages`必须为`client auth`，而`request`为此前`john.csr`文件的base64编码，可以使用命令`cat john.csr | base64 | tr -d "\n"`获取。

查看当前的csr资源并批准：
```bash
[root@xxx ~]# kubectl get csr
NAME   AGE   REQUESTOR          CONDITION
john   49s   kubernetes-admin   Pending
[root@xxx ~]# kubectl certificate approve john
certificatesigningrequest.certificates.k8s.io/john approved
[root@xxx ~]# kubectl get csr
NAME   AGE   REQUESTOR          CONDITION
john   76s   kubernetes-admin   Approved,Issued
```
其中`REQUESTOR`表示谁创建了这个k8s csr请求。最终可看到证书请求获批。

获取用户证书：
```bash
kubectl get csr/john -o yaml
```
其中`status.certificate`即用户证书的base64编码，解码后即可保存为`john.crt`。

创建`Role`和`RoleBinding`为用户赋权：
```bash
kubectl create role developer --verb=create --verb=get --verb=list --verb=update --verb=delete --resource=pods
kubectl create rolebinding developer-binding-john --role=developer --user=john
```
`ClusterRole`和`ClusterRoleBinding`操作类似。注意，证书用户`john`没有命名空间，同服务账号`ServiceAccount`不同。
当然，也可为john所在的用户组赋权。

将用户添加到`kubeconfig`中：
```bash
# 首先，设置用户（及其凭证）
kubectl config set-credentials john --client-key=/path/to/john.key --client-certificate=/path/to/john.crt --embed-certs=true
# 然后，设置上下文，绑定用户和集群关系
kubectl config set-context john@k8s-cluster --cluster=k8s-cluster --user=john
# 最后，切换到新设置的上下文，以用户john方式访问/操作集群k8s-cluster
kubectl config use-context john
```

### 通过webhook对接外部认证提供商
OAuth

## 到达聚合apiserver的请求中如何携带用户信息
文档 [Original Request Username and Group](https://kubernetes.io/docs/tasks/extend-kubernetes/configure-aggregation-layer/#original-request-username-and-group) 中描述了请求经过apiserver转发到聚合apiserver时，
在请求扩展头中携带原始的用户和用户组信息，默认的：
- `X-Remote-Group`扩展头部携带用户组
- `X-Remote-User`扩展头部携带用户

## TODO
- https://jimmysong.io/kubernetes-handbook/guide/authentication.html
- https://learnk8s.io/auth-authz
- https://howieyuen.github.io/docs/kubernetes/kube-apiserver/authentication/
- https://qingwave.github.io/kube-apiserver-authentication-code/
- https://www.styra.com/blog/kubernetes-authorization-webhook/

# 鉴权Authorization

## 判断我是否有权限
```bash
kubectl auth can-i --as=system:serviceaccount:kube-system:replicaset-controller use securitycontextconstraints/anyuid
```

## 判断谁有权限操作
```bash
oc adm policy who-can use securitycontextconstraints/anyuid
```

## 常见操作
```bash
# 查看未认证用户的权限
kubectl get clusterrolebinding -o custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECTS:.subjects | grep unauthen
```

# 安全
## Pod Security Admission
TODO

## 配置container Capabilities
[在 Kubernetes 中配置 Container Capabilities](https://mp.weixin.qq.com/s/cQurKzXBEi-mMaT-lR8Ehg)

## Kubernetes对接容器安全

### CRI接口中LinuxContainerSecurityContext
类型 *LinuxContainerSecurityContext* 定义了Linux系统下容器的安全配置。

其中特权模式（`Privileged` 为`true`）时，策略如下：
```
If set, run container in privileged mode.
Privileged mode is incompatible with the following options. If
privileged is set, the following features MAY have no effect:
1. capabilities
2. selinux_options
4. seccomp
5. apparmor

Privileged mode implies the following specific options are applied:
1. All capabilities are added.
2. Sensitive paths, such as kernel module paths within sysfs, are not masked.
3. Any sysfs and procfs mounts are mounted RW.
4. AppArmor confinement is not applied.
5. Seccomp restrictions are not applied.
6. The device cgroup does not restrict access to any devices.
7. All devices from the host's /dev are available within the container.
8. SELinux restrictions are not applied (e.g. label=disabled).
```

### OCI接口中LinuxDeviceCgroup
*LinuxDeviceCgroup* 定义Linux系统下Device控制组的配置。

crio容器运行时中， `specAddHostDevicesIfPrivileged()` 会为特权容器配置allow为true。

# 操作实例

## 大规模集群实践
* [究竟谁是草台班子？](https://mp.weixin.qq.com/s/ZvG232ale2qwBl1-LFw-Zw)

### 社区优化跟踪
* [support pod namespace index in cache](https://github.com/kubernetes/kubernetes/issues/120778)

## 在大规模集群中优雅的操作

### 集群Pod总数
```bash
for n in $(kubectl get ns --no-headers | awk '{print $1}'); do kubectl get pod -n $n --ignore-not-found | wc -l; done | awk '{s+=$1} END {print s}'
```

### 集群Event总数
```bash
for n in $(kubectl get ns --no-headers | awk '{print $1}'); do kubectl get event -n $n --ignore-not-found | wc -l; done | awk '{s+=$1} END {print s}'
```

### 筛选慢操作list all
```bash
_RESULT_FILE_NAME_=slow-response-kube-apiserver-$(date +"%Y%m%d%H%M%S").csv
echo "count,verb,url,agent,client" >> ${_RESULT_FILE_NAME_}
cat ./kube-apiserver.log* | grep "trace.go:116" | grep -v "ms):$\|etcd3\|cacher list" | sed 's/.*Trace\[.*\]: //g' | grep "/api/v1/events\|/api/v1/nodes,\|/api/v1/pods\|/api/v1/services\|/api/v1/endpoints" | while read -r line
do
    verb=$(echo $line | awk '{print $1}' | sed 's/"//g')
    url=$(echo $line | grep -Eo "url:.*," | cut -d, -f1 | sed 's/url://g')
    agent=$(echo $line | grep -Eo "user-agent:.*," | cut -d, -f1 | sed 's/user-agent://g' | awk '{print $1}')
    client=$(echo $line | grep -Eo "client:.* \(s" | awk '{print $1}' | sed 's/client://g')
    time=$(echo $line | awk '{print $NF}' | sed 's/)://g')

    echo $verb $url $agent $client
done | sort | uniq -c | sed 's/^[ ]*//g' | tr ' ' ',' >> ${_RESULT_FILE_NAME_}
```

### 筛选出最早创建的一组pod（用于onDelete策略的更新）
```bash
STEP=100
kubectl get pod -n foo -l name=bar --sort-by=.status.startTime -owide --no-headers | head -n ${STEP}
```

## 节点维护
```bash
# 排干节点
kubectl drain ${node} --delete-emptydir-data --ignore-daemonsets --force

# 为节点打污点
kubectl taint nodes worker foo:NoSchedule
kubectl taint nodes worker foo=bar:NoExecute
```

## 便捷操作
* 查找某个节点上带某种注解的pod
  ```bash
  NODE_NAME=hehe
  kubectl get pod -A --field-selector spec.nodeName=$NODE_NAME -o json | jq -r '.items[] | select(.metadata.annotations["foo/bar"] != null) | .metadata | .namespace + " " + .name'
  ```

* 查询Pod的uid
  ```bash
  kubectl get pod -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,UID:.metadata.uid
  ```

* 清理`Completed`状态的Pod
  ```bash
  kubectl delete pod --field-selector=status.phase==Succeeded --all-namespaces
  ```

* 清理`Error`状态的Pod
  ```bash
  kubectl delete pod --field-selector=status.phase==Failed --all-namespaces
  ```

* 清理`NodeAffinity`状态的Pod
  ```bash
  kubectl get pod -A -owide | grep NodeAffinity | awk '{print $1" "$2}'  | xargs kubectl delete pod -n $1 $2
  ```

* 找到master节点
  ```bash
  kubectl get node -l node-role.kubernetes.io/master= -o json | jq '.items[].status.addresses[] | select(.type == "InternalIP") | .address' -r
  ```

* 找到worker节点，且不是master节点
  ```bash
  kubectl get node -l node-role.kubernetes.io/worker= -l node-role.kubernetes.io/master!= -o json | jq '.items[].status.addresses[] | select(.type == "InternalIP") | .address' -r
  ```

* 常用操作别名
  ```bash
  alias pod='kubectl get pod -o wide -A'
  alias svc='kubectl get svc -A'
  alias node='kubectl get node -o wide'
  alias kc='kubectl'
  ```

* 统计各节点上Pod数
  ```bash
  function nodePodCnt {
      local tmp_file=$(mktemp)

      kubectl get pod -A -owide --no-headers > ${tmp_file}
      if [ $? -eq 0 ]; then
          for node in $(cat ${tmp_file} | awk '{print $(NF-2)}' | sort | uniq); do
              echo ${node} $(cat ${tmp_file} | grep -cw ${node})
          done
      fi

      rm -f ${tmp_file}
  }
  ```

* base64编码的证书信息
  ```bash
  function b642cert {
      local b64=$1
      echo $b64 | base64 -d | openssl x509 -noout -text
  }
  ```

## event使用独立的etcd集群
```bash
--etcd-servers-overrides="/events#https://1.2.3.1:2369;https://1.2.3.2:2369;https://1.2.3.3:2369"
```

## 模拟list对kube-apiserver进行压测
10qps:
```
#!/bin/bash
while true
do
    for((i = 0; i<10; i++)); do
    {
     timeout 6 kubectl get --raw /api/v1/pods 1>/dev/null
    }&
    done
    sleep 1s
    echo "$(date) start the next loop..."
done
```

## 获取openapi json
```bash
kubectl get --raw /openapi/v2 | jq > openapi.json
```
此后可用*swagger*打开api文档。

## 从secret中获取证书信息
```bash
function b642cert {
  local b64=$1
  echo $b64 | base64 -d | openssl x509 -noout -text
}
```

## 从KubeConfig文件中提取证书秘钥
```bash
# TODO: 兼容配置有多个cluster、多个user的情况，需要通过current-context判断
PATH_TO_KUBECONFIG=/root/.kube/config
cat $PATH_TO_KUBECONFIG  | grep certificate-authority-data | awk '{print $2}' | base64 -d > ca.crt
cat $PATH_TO_KUBECONFIG  | grep client-certificate-data | awk '{print $2}' | base64 -d > tls.crt
cat $PATH_TO_KUBECONFIG  | grep client-key-data | awk '{print $2}' | base64 -d > tls.key
```


## 堆栈文件分析
```bash
# goroutine统计
grep ^goroutine xxx-goroutine-9.log -A 1 | grep -v "^goroutine\|^--" | sort | less
```
## 根据sa生成kubeconfig
```bash
# your server name goes here
server=https://localhost:8443

# sa ns and name
sa_ns=kube-system
sa_name=admin
# the name of the secret containing the service account token goes here
secret_name=$(kubectl get sa -n $sa_ns $sa_name -o json | jq .secrets[] -r | grep -- "-token-" | awk '{print $2}' | tr -d '"')

ca=$(kubectl get -n $sa_ns secret/$secret_name -o jsonpath='{.data.ca\.crt}')
token=$(kubectl get -n $sa_ns secret/$secret_name -o jsonpath='{.data.token}' | base64 --decode)

echo "
apiVersion: v1
kind: Config
clusters:
  - name: default-cluster
    cluster:
      certificate-authority-data: ${ca}
      server: ${server}
contexts:
  - name: default-context
    context:
      cluster: default-cluster
      namespace: default
      user: default-user
current-context: default-context
users:
  - name: default-user
    user:
      token: ${token}" > sa.kubeconfig
```

## kubeconfig跳过服务端证书校验
```bash
clusters:
- cluster:
    server: https://foo.bar:6443
    insecure-skip-tls-verify: true
  name: hehecluster
...
```

## 定制kubectl输出
```bash
# 定制输出
kubectl get pod --sort-by=.status.startTime -o=custom-columns=name:.metadata.name,startTime:.status.startTime
```

## kubectl patch操作

命令行：
```bash
# merge方式
kubectl patch mykind demo --type=merge --subresource status --patch 'status: {conditions: [{type: Degraded, status: "False", reason: AsExpected, message: "everything is ok", lastTransitionTime: "2024-07-11T09:08:47Z"}]}'

# json方式
kubectl patch bmh -n machine-api worker1 --subresource status --type='json' -p='[{"op": "replace", "path": "/status/hardware/hostname", "value": "hehe"}]'

# 删除字段（以pod反亲和举例）
kubectl patch deploy test -p '{"spec":{"template": {"spec": {"affinity": {"podAntiAffinity":null}}}}'
```

从标准输入中打patch：
```bash
cat << EEOOFF | kubectl patch mykind demo --type=merge --subresource status --patch-file=/dev/stdin
status:
  conditions:
  - type: Available
    status: "True"
    lastTransitionTime: "2024-07-11T09:12:23Z"
    reason: AsExpected
    message: |-
      DemoServiceAvailable: All service is available
EEOOFF
```

## 常见操作

```bash
# 查看pod和容器的创建、启动时间
# 输入Pod相关信息
NS=default
POD=test-pod
# 获取ID信息
CID=$(kubectl describe pod -n $NS $POD  | grep cri-o | cut -d/ -f3)
PODUID=$(kubectl get pod -n $NS $POD -o jsonpath='{.metadata.uid}')
# 在Pod所在节点执行，查看pod和容器创建日志
journalctl -u kubelet -u crio | grep "$POD\|$CID\|$PODUID" | grep "RemoteRuntimeService\|Created container\|Creating container\|Created container\|Starting container\|Started container"

# 找到挂载主机根目录的pod
kubectl get pod -A -o=custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,VOLUMES:.spec.volumes | grep hostPath | grep "path:/ " | awk '{print $1" "$2}'

# 找到deploy对应的pod（使用 jq 的 to_entries ）
selector=$(kubectl get deploy -n $ns $name -o jsonpath='{.spec.selector.matchLabels}' | jq 'to_entries[]| .key + "=" + .value' -r | tr '\n' ',' | sed 's/,$//g')
kubectl get pod -n $ns -l $selector

# 批量找到deploy对应的pod
for deploy in $(kubectl get deploy -A -o=custom-columns=NS:.metadata.namespace,NAME:.metadata.name,REPLICA:.spec.replicas | grep " 2$" | awk '{print $1"/"$2}'); do
    ns=$(echo $deploy | cut -d/ -f1)
    name=$(echo $deploy | cut -d/ -f2)
    selector=$(kubectl get deploy -n $ns $name -o jsonpath='{.spec.selector.matchLabels}' | jq 'to_entries[]| .key + "=" + .value' -r | tr '\n' ',' | sed 's/,$//g')
    nodes=$(kubectl get pod -owide -n $ns -l $selector -o=custom-columns=NODE:.spec.nodeName --no-headers | tr '\n' ' ')
    printf "%-30s %-50s %s\n" "$ns" "$name" "$nodes"
done


# 手动拉取pod使用的容器镜像
function man_pull {
    local ns=$1
    local pod=$2

    for i in $(kubectl get pod -n ${ns} ${pod} -o json | jq .spec.containers[].image -r | sort | uniq); do
        podman pull $i
    done
}

# 停止一个节点上的容器服务和所有容器
systemctl stop kubelet
crictl ps -q | xargs crictl stop

# 以创建时间排序
kubectl get pod -A --sort-by .metadata.creationTimestamp

# 查看API版本
kubectl api-versions
# 注意，OpenShift的Controller-Manager和Scheduler组件整合为controller组件，并使用https://x.x.x.x:8444/healthz作为健康检查endpoint
# OpenShift平台查看controller的健康情况
curl -k https://10.125.30.224:8444/healthz
# 查看集群组件信息
kubectl get componentstatus
kubectl get --raw /api/v1/componentstatuses/controller-manager | jq
kubectl get --raw /apis/metrics.k8s.io/v1beta1/namespaces/openshift-sdn/pods/sdn-5bbcx | jq
kubectl get --raw /apis/custom.metrics.k8s.io/v1beta1/namespaces/default/pods/*/http_requests | jq
./kubectl --server=https://kubernetes/ --certificate-authority=/tmp/openssl/ca.crt --client-certificate=/tmp/openssl/client.crt --client-key=/tmp/openssl/client.key get pod
/opt/bin/kubectl -s 127.0.0.1:8888 get pod -o wide
/opt/bin/kubectl -s 127.0.0.1:8888 describe ep
# 查看Pod信息，定位问题
/opt/bin/kubectl -s 127.0.0.1:8888 describe pod        
/opt/bin/kubectl -s 127.0.0.1:8888 cluster-info
/opt/bin/kubectl -s 127.0.0.1:8888 get services
/opt/bin/kubectl -s 127.0.0.1:8888 get rc
# 自定义信息的输出列
/opt/bin/kubectl -s 127.0.0.1:8888 get nodes -o=custom-columns=NAME:.metadata.name,IPS:.status.addresses    
kubelet --help 2>&1 | less
# node状态为Ready,SchedulingDisabled时，手工开启调度
/opt/bin/kubectl -s 127.0.0.1:8888 uncordon 172.25.18.13
# 查看Pod web-1中前一个ruby容器的日志
kubectl logs -p -c ruby web-1  
# 支持json格式解析
kubectl get svc mysql-node1 -o jsonpath='{.spec.clusterIP}'
kubectl get pods -n default -l app=foo -o=jsonpath='{range .items[*]}{.metadata.name} {end}'
kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'
/opt/bin/kubectl -s 127.0.0.1:8888 delete -f /opt/bin/confFile-cluster/openstack-new-rc.yaml
# 使用--field-selector过滤
kubectl get pod -A --field-selector spec.nodeName=zy-sno
# go template示例
kubectl get ns -o jsonpath='{range .items[*]} {.metadata.name}{"\n"} {end}'
kubectl get pod -A --field-selector spec.nodeName=$(hostname) -o jsonpath='{range .items[?(.spec.dnsPolicy=="Default")]}{.metadata.namespace}{"/"}{.metadata.name}{"\n"}{end}'
kubectl get pod -A --field-selector spec.nodeName=$(hostname) -o jsonpath='{range .items[?(.spec.hostNetwork==true)]}{.metadata.namespace}{"/"}{.metadata.name}{"\n"}{end}'
kubectl get nodes --selector='node-role.kubernetes.io/master' -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}'
kubectl get pod -o jsonpath='{.spec.containers[?(@.name=="dns")].image}'
kubectl get pod -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'
kubectl get apirequestcounts -o jsonpath='{range .items[?(@.status.removedInRelease!="")]}{.status.removedInRelease}{"\t"}{.status.requestCount}{"\t"}{.metadata.name}{"\n"}{end}'
kubectl get apirequestcounts ingresses.v1beta1.networking.k8s.io \
  -o jsonpath='{range .status.last24h..byUser[*]}{..byVerb[*].verb}{","}{.username}{","}{.userAgent}{"\n"}{end}'
# 查看所有Pod
kubectl get pod | grep -v NAME | awk '{print $1}'      
# 查看Pod的运行状态
kubectl get pod ceportalrc-n5sqd -o template --template={{.status.phase}}          
# 查看Node的操作系统信息
kubectl get node 172.25.18.24 -o template --template={{.status.nodeInfo.osImage}}  
# 查看容器的log
kubectl logs --namespace="kube-system" kube-dns-v17.1-rc1-27sj0 kubedns  
kubectl drain ${node} --delete-emptydir-data --ignore-daemonsets --force
kubectl uncordon ${node}
# 给name为172.25.18.22的node打标签node: node3，kube-dns依赖于这个标签的。
kubectl label node 172.25.18.22 node=node3
kubectl label --overwrite node 172.25.19.119 nodeType=cellClus
# 删除节点的cellGrp标签
kubectl label node 172.25.19.117 cellGrp-  
# k8s直接进容器
kubectl exec -it <pod名称> [-c <pod中容器名称>] <sh | bash>
# https://kubernetes.io/docs/tasks/debug-application-cluster/get-shell-running-container/
# 其中双横线--将k8s命令同希望容器里执行的命令分隔开
kubectl exec <pod> -- /node-cache -help  
# 示例，通过别名，方便的使用工具pod里的命令
alias ceph='kubectl -n rook-ceph exec $(kubectl -n rook-ceph get pod -l "app=rook-ceph-tools" -o jsonpath='{.items[0].metadata.name}') -- ceph'
# 查看/修改RBAC
kubectl edit clusterrole   
# 查看事件
kubectl get events         
# 过滤查看Warning类型的事件
kubectl get events --field-selector type=Warning
# 过滤查看异常类型的事件
kubectl get events --field-selector type!=Normal
# 格式化输出event
kubectl get event -A --sort-by=.firstTimestamp -o=custom-columns=NS:.metadata.namespace,NAME:.metadata.name,FirstSeen:.firstTimestamp,LastSeen:.lastTimestamp,REASON:.reason
# 过滤查看某个pod的事件
kubectl get event --namespace ns --field-selector involvedObject.kind=Pod --field-selector involvedObject.name=xxx-yyy
curl  -s 'http://1.2.3.4:8080/api/v1/namespaces/default/pods?labelSelector=app=rabbitmq,node=n2' | jq '.items[].metadata.name' | tr -d '"'

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

# 通过文件创建secret，其中指定secret中的键/文件名为htpasswd
kubectl create secret generic htpass-secret --from-file=htpasswd=</path/to/users.htpasswd> -n kube-system

## 通过token直接访问apiserver
# 找到 default sa的携带token信息的secrets
kubectl get sa default -o yaml  
# 直接从secrets中获取TOKEN
kubectl get secrets default-token-xxxxx -o jsonpath='{.data.token}' | base64 -d
# 从secrets中复原证书和秘钥
kubectl get secrets -n cattle-system tls-cert -o jsonpath='{.data.cert\.pem}' | base64 -d > cert.pem    
NSS_SDB_USE_CACHE=yes curl -H "Authorization: Bearer ${TOKEN}" -k https://10.100.0.1/api/

# Pod（容器）里直接获取token的方法
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NSS_SDB_USE_CACHE=yes curl -s -H "Authorization: Bearer ${TOKEN}" -k https://10.100.0.1/api/v1/nodes?labelSelector=nodeType%3Dcontroller | jq -r .items[].metadata.name

# 从SA(serviceaccount)处获取token的方法
NS=default
SA=admin
TOKEN=$(kubectl get secrets -n ${NS} $(kubectl get sa -n ${NS} ${SA} -o jsonpath='{.secrets[0].name}') -o jsonpath='{.data.token}' | base64 -d)

# kubectl使用token
# XXX：需要说明的，如果有~/.kube/config文件，kubectl还是优先使用该kubeconfig文件
kubectl get pod --token ${TOKEN} -s https://api.foo.bar:6443 --insecure-skip-tls-verify

# 模仿Pod内使用in-cluster配置访问apiserver
NS=default
POD=test
TOKEN=$(kubectl exec -n ${NS} ${POD} -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -H "Authorization: Bearer ${TOKEN}" -k https://kubernetes.default.svc:443/api/v1/nodes


# 设置默认StorageClass
kubectl patch storageclass gold -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'

```

## 资源遍历

### 遍历列出所有的资源类型及支持的操作
```bash
# do core resources first, which are at a separate api location
api="core"
kubectl get --raw /api/v1 | jq -r --arg api "$api" '.resources | .[] | "\($api) \(.name): \(.verbs | join(" "))"'

# now do non-core resources
APIS=$(kubectl get --raw /apis | jq -r '[.groups | .[].name] | join(" ")')
for api in $APIS; do
    version=$(kubectl get --raw /apis/$api | jq -r '.preferredVersion.version')
    kubectl get --raw /apis/$api/$version | jq -r --arg api "$api" '.resources | .[]? | "\($api) \(.name): \(.verbs | join(" "))"'
done
```

### 遍历所有pod
```bash
for n_p in $(kubectl get pod -A | sed 1d | awk '{print $1":"$2}'); do
n=$(echo $n_p | cut -d: -f1)
p=$(echo $n_p | cut -d: -f2)
echo $n  $p
kubectl get pod -n $n $p -o json | jq .spec.containers[].imagePullPolicy -r 2>/dev/null
kubectl get pod -n $n $p -o json | jq .spec.initContainers[].imagePullPolicy -r 2>/dev/null
echo
done
```

### 遍历所有pod及其容器
```bash
pod_temp_file=$(mktemp pod_temp.XXXXX)
kubectl get namespace -o json | jq -r '.items[].metadata.name' | while read -r ns; do
    kubectl get pod -n $ns -o json | jq -r '.items[].metadata.name' | while read -r pod; do
        kubectl get pod -n $ns $pod -o json > $pod_temp_file
        jq -r '.spec | select(.initContainers != null) |.initContainers[].name' $pod_temp_file | while read -r ic; do
            echo $ns $pod $ic
        done
        jq -r '.spec | select(.containers != null) | .containers[].name' $pod_temp_file | while read -r c; do
            echo $ns $pod $c
        done
    done
done
rm -f $pod_temp_file
```

### 遍历所有工作负载
```bash
WorkLoads="ds deploy rc sts"
for wl in $(echo $WorkLoads); do
echo "============== $wl =============="
for n_i in $(kubectl get $wl -A | sed 1d | awk '{print $1":"$2}'); do
n=$(echo $n_i | cut -d: -f1)
i=$(echo $n_i | cut -d: -f2)
echo $n $i : $(kubectl get $wl -n $n $i -o json | jq .spec.template.spec.containers[].imagePullPolicy -r 2>/dev/null) $(kubectl get $wl -n $n $i -o json | jq .spec.template.spec.initContainers[].imagePullPolicy -r 2>/dev/null)
done
done
```

### 遍历一个命名空间下所有资源
```bash
NAMESPACE=default
kubectl api-resources --verbs=list --namespaced -o name \
| xargs -n 1 kubectl get --show-kind --ignore-not-found -n ${NAMESPACE}

# 统计
NAMESPACE=default
for t in $(kubectl api-resources --verbs=list --namespaced -o name); do echo "$t: $(kubectl get $t --ignore-not-found -n ${NAMESPACE} | wc -l)"; done
```

### 遍历一个命名空间下所有资源的label和annotations
```bash
NAMESPACE=default
for api in $(kubectl api-resources --verbs=list --namespaced -o name); do
kubectl get ${api} --ignore-not-found -n ${NAMESPACE} -o json | jq .items[].metadata.labels
done
for api in $(kubectl api-resources --verbs=list --namespaced -o name); do
kubectl get ${api} --ignore-not-found -n ${NAMESPACE} -o json | jq .items[].metadata.annotations
done
```

### 遍历所有区分命名空间的资源的内容
```bash
for k in $(kubectl api-resources --verbs=list --namespaced -o name); do
    for ns in $(kubectl get ns -o custom-columns=NAME:.metadata.name --no-headers); do
        for n in $(kubectl get --ignore-not-found -o custom-columns=NAME:.metadata.name --no-headers $k -n $ns 2>/dev/null); do
            output=$(kubectl get $k -n $ns $n -o yaml 2>/dev/null | grep hehe)
            if [ "$output" != "" ]; then
                echo $k $ns $n "$output"
            fi
        done
    done
done
```

### 遍历所有跨命名空间的资源
```bash
kubectl api-resources --verbs=list --namespaced=false -o name \
| xargs -n 1 kubectl get --show-kind --ignore-not-found
```

### 遍历所有跨命名空间的资源的label和annotations
```bash
for api in $(kubectl api-resources --verbs=list --namespaced=false -o name); do
kubectl get ${api} --ignore-not-found -o json | jq .items[].metadata.labels
done
for api in $(kubectl api-resources --verbs=list --namespaced=false -o name); do
kubectl get ${api} --ignore-not-found -o json | jq .items[].metadata.annotations
done
```

### 遍历所有跨命名空间的资源的内容
```bash
for k in $(kubectl api-resources --verbs=list --namespaced=false -o name); do
    for n in $(kubectl get --ignore-not-found -o custom-columns=NAME:.metadata.name --no-headers $k 2>/dev/null); do
        output=$(kubectl get $k $n -o yaml 2>/dev/null | grep hehe)
        if [ "$output" != "" ]; then
            echo $k $n "$output"
        fi
    done
done
```

### 遍历所有pod的cpu request配置
```bash
# 统计pod的cpu request
POD_TEMP_RESULT_FILE=$(mktemp)

kubectl get pod -A -o json > $POD_TEMP_RESULT_FILE

cat $POD_TEMP_RESULT_FILE | jq -r '.items[] | .metadata.namespace + " " + .metadata.name' | while read -r ns pod; do
    pod_yaml=$(cat $POD_TEMP_RESULT_FILE | jq -r --arg ns "$ns" --arg pod "$pod" '.items[] | select(.metadata.namespace == $ns) | select(.metadata.name == $pod)')

    for c in $(echo $pod_yaml | jq -r '.spec.containers[].name'); do
        c_yaml=$(echo $pod_yaml | jq -r --arg c "$c" '.spec.containers[] | select(.name == $c)')
        cpu_req=$(echo $c_yaml | jq -r .resources.requests.cpu)

        printf "%-46s %-64s %-40s %s\n" $ns $pod $c $cpu_req
    done
done


rm -f $POD_TEMP_RESULT_FILE
```

## 客户端访问集群时context配置

```bash
# 注意，ca.crt、client.crt和client.key需要来自目标集群，例如配置中的deploy-cluster
kubectl config set-cluster deploy-cluster --server=https://${KUBE_APISERVER_IP_OR_DOMAINNAME}:${KUBE_APISERVER_PORT} --certificate-authority=./ca.crt --embed-certs=true

kubectl config set-credentials deploy-user --client-key=./client.key --client-certificate=./client.crt --embed-certs=true
# 或者
kubectl config set-credentials local-cluster-user --token=eyJhb

kubectl config set-context deploy-context --cluster=deploy-cluster --user=deploy-user --namespace=default

# 切换到deploy-cluster集群，注意，后面的kubectl都是在deploy-cluster上操作
kubectl config use-context deploy-context
```



## ConfigMap使用

将配置/模板文件保存到configMap并提取出来

~~~
kubectl create configmap hehe --from-file=mysql-node-rc-template.yaml
kubectl get cm hehe -o jsonpath='{.data.mysql-node-rc-template\.yaml}'
~~~

创建加更新ConfigMap

~~~
kubectl create configmap -n default os-watchdog-config --from-file=i18n_zh.json --from-file=i18n_en.json -o yaml --dry-run | kubectl apply -f -
~~~

## 日志相关配置

```bash
--log-dir=/var/log/kubernetes --logtostderr=false --v=4
```

## 提升集群HA性能
kubelet设置 `--node-status-update-frequency` 参数，例如从默认值10s调整为5s，提升节点状态变化感知效率。
kube-controller-manager设置 `--node-monitor-grace-period` 参数，例如从默认值40s调整为16s，提升节点变化响应速度。



## 强制删除Pod

```bash
kubectl delete pods <pod> --grace-period=0 --force
```

## Pod中获取PodIP的方法
通过 [Downward API](https://kubernetes.io/docs/concepts/workloads/pods/downward-api/) ，可在Pod中获取例如PodIP之类的信息。
这些信息属于Pod/容器自己的信息，容器初始化和运行的时候，获取这些信息有助于灵活配置。

有两种方式将这些信息提供到Pod内：
* [以环境变量方式](https://kubernetes.io/docs/tasks/inject-data-application/environment-variable-expose-pod-information/)
* [以文件/volume方式](https://kubernetes.io/docs/tasks/inject-data-application/downward-api-volume-expose-pod-information/) ，特别适用于**标签**和**注解**

例如以环境变量方式：
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

注意:
1. 仅kubernetes v1.8+版本支持。
2. 仅支持部分字段，详见链接 [Downward API](https://kubernetes.io/docs/concepts/workloads/pods/downward-api/)
3. 容器中使用环境变量，在*args*中若还未被容器内shell解析则应指定为`$(ENV_VAR_KEY)`，若在shell执行器后指定则为`${ENV_VAR_KEY}`

## emptyDir在宿主机上的路径

```bash
# emptyDir文件夹路径
/var/lib/kubelet/pods/<pod uuid>/volumes/kubernetes.io~empty-dir

# 查找一个emptyDir文件夹中的文件，一种简便（但效率较低）的查找方法
find /var/lib/kubelet/pods/*/volumes/kubernetes.io~empty-dir -name "file-name"
```

### 节点上emptyDir用量统计
```bash
for d in $(sudo find /var/lib/kubelet/pods -type d -name "*empty-dir*" 2>/dev/null); do
    sudo du -sh $d
done

# 排除掉空文件夹
for d in $(sudo find /var/lib/kubelet/pods -type d -name "*empty-dir*" 2>/dev/null); do
    sudo du -sh $d
done | grep -v "^0\>"
```

### 远程到节点统计emptyDir用量
一个复杂的，借助`sh -c`远程执行`find`、`sudo`、`du`命令的示例：
```bash
ssh $node_ip 'sh -c "sudo find /var/lib/kubelet/pods/ -maxdepth 3 -name "kubernetes.io~empty-dir" -type d -exec du -s {} \;"' | grep -vw ^0 | awk '{print $2}'
```

## FC存储多路径的PV配置

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


## 编译kubelet
使用构建镜像编译：
```bash
docker run -it --privileged \
    -v ${PWD}/kubernetes:/go/src/github.com/kubernetes/kubernetes \
    -e GOPATH=/go \
    -w /go/src/github.com/kubernetes/kubernetes k8s.gcr.io/build-image/kube-cross:v1.15.8-legacy-1 sh
# 需要编什么架构，就export什么架构：
#   export KUBE_BUILD_PLATFORMS=linux/arm64
export KUBE_BUILD_PLATFORMS=linux/amd64
make WHAT=cmd/kubelet GOLDFLAGS=""
```

## 获取k8s控制面组件指标

**kube-apiserver**:
```bash
# kube-apiserver
kubectl get --raw /metrics
```

**kubelet**:
```bash
# 从kubeconfig里拿ca.crt user.crt user.key
curl --cacert ./ca.crt --cert ./user.crt --key ./user.key https://x.x.x.x:10257/metrics -k
```

## kubeadm部署的集群的操作
```bash
# 从kubelet的metrics里，查看编译时用的golang版本：
curl -sk https://127.0.0.1:10250/metrics --cacert /etc/kubernetes/pki/ca.crt --cert /etc/kubernetes/pki/apiserver-kubelet-client.crt --key /etc/kubernetes/pki/apiserver-kubelet-client.key | grep go_info
```

## kube-apiserver内部本地访问客户端
检查证书有效期：
```bash
MASTER_IP=1.2.3.4
KUBE_APISERVER_PORT=6443
curl --resolve apiserver-loopback-client:${KUBE_APISERVER_PORT}:${MASTER_IP} -k -v https://apiserver-loopback-client:${KUBE_APISERVER_PORT}/healthz
```

详见文章[kubernetes 究竟有没有 LTS？](https://mp.weixin.qq.com/s/3dATYVtgcQDxEOKR5XNofg)

## 读取 kubelet_internal_checkpoint
```bash
jq --arg PodUID "xxx" '.Data.PodDeviceEntries[] | select(.PodUID == $PodUID) | select(.ContainerName == "hehe") | select(.ResourceName == "foo.bar/gpu")' /var/lib/kubelet/device-plugins/kubelet_internal_checkpoint | jq '.DeviceIDs["111"]'[]
```

# 最佳实践
## 使用finalizers拦截资源删除

### 手动清理finalizers
```bash
kubectl patch pod xxx --type='json' -p='[{"op": "remove", "path": "/metadata/finalizers"}]'
```

## 资源限制
### 容器进程数限制pids
TODO:
* https://kubernetes.io/docs/concepts/policy/pid-limiting/
* https://access.redhat.com/articles/7033551

当kubelet的`podPidsLimit`设置为4096时：
```bash
cd /sys/fs/cgroup/pids/kubepods.slice
# 查看一个pod的pids设置
for p in $(find . -name "pids.max"); do echo "$(cat $p) $p"; done | grep kubepods-burstable-podxxx.slice
203348 ./kubepods-burstable.slice/kubepods-burstable-podxxx.slice/crio-111.scope/pids.max
203348 ./kubepods-burstable.slice/kubepods-burstable-podxxx.slice/crio-conmon-222.scope/pids.max
203348 ./kubepods-burstable.slice/kubepods-burstable-podxxx.slice/crio-222.scope/pids.max
max ./kubepods-burstable.slice/kubepods-burstable-podxxx.slice/crio-<sandbox pod>/pids.max
4096 ./kubepods-burstable.slice/kubepods-burstable-podxxx.slice/pids.max
203348 ./kubepods-burstable.slice/kubepods-burstable-podxxx.slice/crio-conmon-111.scope/pids.max
```
可看到：
1. sandbox pod的pids未设限，pids.max置为max
2. 业务容器默认置为`203348`
3. 整个pod的pids.max被置为4096

代码实现详见：*pkg/kubelet/cm/pod_container_manager_linux.go*

## HPA
参考链接[kubernetes-hpa-configuration-guide](https://segment.com/blog/kubernetes-hpa-configuration-guide/)

## 集群内通过svc访问外部服务
```bash
cat << EEOOFF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: etcd
---
apiVersion: v1
kind: Endpoints
metadata:
  name: etcd
  namespace: etcd
subsets:
- addresses:
  - ip: 1.2.3.4
  - ip: 1.2.3.5
  - ip: 1.2.3.6
  ports:
  - port: 2379
---
apiVersion: v1
kind: Service
metadata:
  labels:
    k8s-app: etcd
  name: etcd
  namespace: etcd
spec:
  ports:
  - name: etcd
    port: 2379
    protocol: TCP
    targetPort: 2379
EEOOFF
```

# 性能调优
## 读懂监控指标
### etcd监控指标
告警经验值：

| 指标                           | label                    | 说明  | 告警值     |
|------------------------------|--------------------------|-----|---------|
| grpc_server_handling_seconds | grpc_method="Txn"        |     | P99 0.5 |
| grpc_server_handling_seconds | grpc_method="Range"      |     | P99 0.5 |
| grpc_server_handling_seconds | grpc_method="LeaseGrant" |     | P99 0.5 |
| grpc_server_handling_seconds | grpc_method="MemberList" |     | P99 0.5 |

### kube-apiserver监控指标

| 指标                            | label           | 说明                                                                 | 告警值 |
|-------------------------------|-----------------|--------------------------------------------------------------------|-----|
| etcd_db_total_size_in_bytes   |                 | Total size of the etcd database file physically allocated in bytes |     |
| etcd_bookmark_counts          | resource        | Number of etcd bookmarks (progress notify events) split by kind    |     |
| etcd_lease_object_counts      |                 | Number of objects attached to a single etcd lease                  |     |
| etcd_request_duration_seconds | operation, type | Etcd request latency in seconds for each operation and object type |     |
| apiserver_storage_objects     | resource        | Number of stored objects at the time of last check split by kind   |     |


### kube-controller-manager监控指标

### kube-scheduler监控指标

### kubelet监控指标

## 内存优化
[k8s client-go内存优化](https://blog.ayanamist.com/2022/10/28/k8s-informer-mem-optimize.html):
* 优先使用Protobuf而不是JSON
* 流式list，避免informer首次list时置`resourceVersion=0`，全量拉取数据并一起做反序列化，相关[KEP-3157: allow informers for getting a stream of data instead of chunking](https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/3157-watch-list)

## 查看defaultCpuSet核上CPU使用量
```bash
function default_cores {
    input=$(cat /var/lib/kubelet/cpu_manager_state | jq -r .defaultCpuSet)
    IFS=',' read -ra ADDR <<< "$input"
    for item in "${ADDR[@]}"; do
        if [[ "$item" == *"-"* ]]; then
            start=$(echo "$item" | cut -d'-' -f1)
            end=$(echo "$item" | cut -d'-' -f2)
            for (( i=$start; i<=$end; i++ )); do
                echo $i
            done
        else
            echo $item
        fi
    done
}

function cores_util {
    temp_result=$(mktemp)
    ps -eLo pid,tid,comm,pcpu,psr > $temp_result
    for c in $(default_cores); do
        util=$(cat $temp_result | grep " $c$" | awk '{s+=$4}END{print s}')
        printf "Core %2d ============================== total usage %s%%\n" $c $util
        cat $temp_result | grep " $c$" | sort -rnk4 | head -n 3
    done

    rm -f $temp_result
}
```

# Deep Dive系列
## kube-apiserver

### 服务启动流程
起点`kubernetes/cmd/kube-apiserver/app/server.go`中`CreateServerChain()` 。

依次经过*Aggregator*、 *KubeAPIServer*、 *APIExtensionServer*三个组件处理请求。

### 服务端fieldSelector
XXX TODO

### REST Storage
`kubernetes/pkg/registry/core/rest/storage_core.go`中`NewLegacyRESTStorage` 。

### 安装API及其REST Storage
`vendor/k8s.io/apiserver/pkg/server/genericapiserver.go`中`InstallAPIGroups`和`InstallLegacyAPIGroup`

通过*go-restful*实现API服务，*go-restful*的*Container*在`vendor/k8s.io/apiserver/pkg/server/handler.go`中`NewAPIServerHandler`初始化。

`APIGroupVersion`的`Storage`中，有该*GroupVersion*下所有*resources*的`rest.Storage`。

### API定义和版本
```golang
// Pod is a collection of containers, used as either input (create, update) or as output (list, get).
type Pod struct {
	metav1.TypeMeta
	// +optional
	metav1.ObjectMeta

	// Spec defines the behavior of a pod.
	// +optional
	Spec PodSpec

	// Status represents the current information about a pod. This data may not be up
	// to date.
	// +optional
	Status PodStatus
}
```
其中：
- **继承**了`metav1.TypeMeta`和`metav1.ObjectMeta`，即直接拥有通用属性和方法，实现`runtime.Object`等接口
- **组合**了`PodSpec`和`PodStatus`，指定该资源特性属性

API版本：
- **外部**版本：`staging/src/k8s.io/api/core/v1/types.go`
- **内部**版本：`pkg/apis/core/types.go`

`k8s.io/apimachinery/pkg/runtime/serializer/versioning/versioning.go`中`codec`实现：
- 内外部版本的转化
- 序列化、反序列化

### 序列化和反序列化
_json_、_protobuf_、*yaml*格式的序列化和反序列化实现在`staging/src/k8s.io/apimachinery/pkg/runtime/serializer`中。

#### TypeMeta的反序列化
以*json*为例，在`staging/src/k8s.io/apimachinery/pkg/runtime/serializer/json/meta.go`的`SimpleMetaFactory.Interpret()`中，
借助`go/src/encoding/json/decode.go`实现对`metav1.TypeMeta`的反序列化，获取*GVK* 。

#### 外部版本的序列化和反序列化
`staging/src/k8s.io/apimachinery/pkg/runtime/serializer/json/json.go`中`Serializer.Decode()` ，实现外部版本的序列化和反序列化操作。

#### codec和codec factory
[TODO](https://cloud.tencent.com/developer/article/1891182)

*codec*将内部版本转换为外部版本，并序列化。

`staging/src/k8s.io/apimachinery/pkg/runtime/serializer/versioning/versioning.go`：
```golang
type codec struct {
	encoder   runtime.Encoder
	decoder   runtime.Decoder
	convertor runtime.ObjectConvertor
	creater   runtime.ObjectCreater
	typer     runtime.ObjectTyper
	defaulter runtime.ObjectDefaulter

	encodeVersion runtime.GroupVersioner
	decodeVersion runtime.GroupVersioner

	identifier runtime.Identifier

	// originalSchemeName is optional, but when filled in it holds the name of the scheme from which this codec originates
	originalSchemeName string
}
```

`CodecFactory`环境方法：
* `DecoderToVersion`，返回反序列化并转化为内部版本的`Decoder`。
* `EncoderForVersion`，返回转换为特定外部版本并序列化的`Encoder`，编码过程中首先将对象(一般为内部版本)转化为目标版本，再序列化到响应数据流中。

### 资源schema
参见[链接](https://cloud.tencent.com/developer/article/1902710) 。

GVK和资源model的对应关系，资源model的默认值，资源在不同版本间转化的函数等，均由资源schema维护。

### 健康检查/healthz
检查三个方面：
1. 初始配置时，增加默认检查方法，包括`k8s.io/apiserver/pkg/server/healthz`中`PingHealthz`和`LogHealthz`
2. 检查存储后端（etcd）是否健康，使用`k8s.io/apiserver/pkg/storage/storagebackend/factory`中`CreateHealthCheck()`创建检查方法
3. 若通过`--encryption-provider-config`配置KMS加密，使用`k8s.io/apiserver/pkg/server/options/encryptionconfig`中`GetKMSPluginHealthzCheckers()`创建检查方法

```
[+]ping ok
[+]log ok
[-]etcd failed: reason withheld
[+]poststarthook/start-kube-apiserver-admission-initializer ok
[+]poststarthook/generic-apiserver-start-informers ok
[+]poststarthook/start-apiextensions-informers ok
[+]poststarthook/start-apiextensions-controllers ok
[+]poststarthook/crd-informer-synced ok
[+]poststarthook/bootstrap-controller ok
[+]poststarthook/rbac/bootstrap-roles ok
[+]poststarthook/scheduling/bootstrap-system-priority-classes ok
[+]poststarthook/apiserver/bootstrap-system-flowcontrol-configuration ok
[+]poststarthook/start-cluster-authentication-info-controller ok
[+]poststarthook/start-kube-aggregator-informers ok
[+]poststarthook/apiservice-registration-controller ok
[+]poststarthook/apiservice-status-available-controller ok
[+]poststarthook/kube-apiserver-autoregistration ok
[+]autoregister-completion ok
[+]poststarthook/apiservice-openapi-controller ok
healthz check failed
```

### 就绪检查/readyz
1. `kube-apiserver`的`shutdown-delay-duration`参数控制优雅退出。
2. 在`kube-apiserver`退出期间，就绪检查失败、但健康检查ok，确保*in flight*的请求能正常处理，但不要有新的建连和请求上来
3. `kube-apiserver`的`shutdown-send-retry-after`控制在优雅退出期间，有新请求到来时，返回`retry`
4. 实现逻辑在`k8s.io/apiserver/pkg/server/healthz`，详见`func (s *GenericAPIServer) AddReadyzChecks(checks ...healthz.HealthChecker) error`

### node authorizer实现
`plugin/pkg/auth/authorizer/node/graph.go`中为同node相关的资源创建的graph：
```
            volume attachment -> node
                          pod -> node
                sa     -> pod         // pod service account
                secret -> pod         // every secret referenced by the pod, e.g. ImagePullSecrets, Container Env from secret, Volumes' secret ref
                cm     -> pod         // every cm referenced by the pod, e.g. Container Env from cm, cm volumes
                pvc    -> pod         // every pvc referenced by the pod in volumes
          pv -> pvc
secret -> pv                          // every secret referenced by the PV spec
```
在 `authorization-mode` 的 `node` 中，根据上述资源与节点的关系图`graph`判断节点是否有访问权限。

## kube-controller-manager

### 配置和初始化

### leader选举

### 核心Controller

## kube-scheduler

### 配置和初始化

### leader选举

### 资源调度

## kubelet

### 配置和初始化
`kubeletConfiguration v1beta1`的默认配置在*pkg/kubelet/apis/config/v1beta1/defaults.go* 中 *SetDefaults_KubeletConfiguration()* 设置。

### PLEG

### 调用CRI接口
容器拉起流程 `kubelet` --cri--> `cri-o` --oci--> `runc`。

* **_cri_**接口`k8s.io/cri-api/pkg/apis/runtime/v1/api.pb.go`，例如由`LinuxContainerResources`定义容器的资源配置。
* **_oci_**接口`github.com/opencontainers/runtime-spec/specs-go/config.go`，例如由`LinuxResources`定义容器的资源配置。


### （间接）通过CNI接口管理网络

### 通过CSI管理存储

### 设备和资源管理

#### 资源计算和预留

##### 为容器进程设置oom_score_adj
针对不同服务质量和优先级的pod，在创建容器（拉起进程时）kubelet会设置不同的*oom_score_adj*，具体的：
* *Guaranteed* 为 -997
* *BestEffort* 为 1000
* *Burstable* 根据公式 `min(max(2, 1000 - (1000 * memoryRequestBytes) / machineMemoryCapacityBytes), 999)` 计算得出
* *system-node-critical* 优先级的Pod，也设置为 -997

进一步阅读:
* [Node out of memory behavior](https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/#node-out-of-memory-behavior)
* [代码GetContainerOOMScoreAdjust()](https://github.com/kubernetes/kubernetes/blob/fa88c0b7796170eeff5686ae1d7d0f2f3f0df5de/pkg/kubelet/qos/policy.go#L43)


#### Topology Manager

#### CPU Manager

##### 遍历所有Pod的cpuset配置
```bash
# 遍历打印所有容器的cpuset配置，注意需要特权用户执行
printf "%-44s %-64s %-48s %s\n" NAMESPACE POD CONTAINER CPUSET
for cid in $(crictl ps -q); do
    scope=$(find /sys/fs/cgroup/cpuset/ -name "crio-${cid}.scope")
    if [ "${scope}" != "" ]; then
        cpuset=$(cat ${scope}/cpuset.cpus)
        cinfo=$(crictl inspect $cid | jq -r '.status | .labels["io.kubernetes.pod.namespace"] + " " + .labels["io.kubernetes.pod.name"] + " " + .labels["io.kubernetes.container.name"]')
        printf "%-44s %-64s %-48s %s\n" $cinfo $cpuset
    else
        echo "Error: missing scope for $cid" >> /dev/stderr
    fi
done
```

#### Memory Manager

#### Device Manager
Device Manager调用Device Plugin，完成扩展设备的发现、分配。

### 节点优雅关机 GracefulNodeShutdown
`GracefulNodeShutdown`

## 库函数和实操
### 特性门featuregate
featuregate在`pkg/features/kube_features.go`中定义。

### 处理runtime.Object
#### 获取meta.Object信息
方法1，将 *runtime.Object* 转成 *unstructured.Unstructured* :
```golang
import (
    "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
    "k8s.io/apimachinery/pkg/runtime"
)

func xxx() {
    var obj runtime.Object
    ...
    innerObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
    if err == nil {
        u := &unstructured.Unstructured{Object: innerObj}
        klog.Infof("%s %s", u.GroupVersionKind(), klog.KObj(u))
    } else {
        klog.Infof("%v", obj)
    }
    ...
}
```

方法2，使用*k8s.io/apimachinery/pkg/api/meta*的*NewAccessor()* :
```golang
import (
    "k8s.io/apimachinery/pkg/api/meta"
    "k8s.io/apimachinery/pkg/runtime"
)

func xxx() {
    var obj runtime.Object
    ...
    accessor := meta.NewAccessor()
    kind, _ := accessor.Kind(obj)
    ...
}

// 或者，直接获取meta.Object
func yyy() {
    var obj runtime.Object
    ...
	meta, err := meta.Accessor(obj)
	if err != nil {
		return "", fmt.Errorf("object has no meta: %v", err)
	}
	if len(meta.GetNamespace()) > 0 {
		return meta.GetNamespace() + "/" + meta.GetName(), nil
	}
	return meta.GetName(), nil
}
```

# Debug
```bash
# 开启apiserver proxy
# 注意，因示例和debug原因开启的disable-filter选项，会带来严重的安全问题，需谨慎
# 默认端口8001
kubectl proxy --address=0.0.0.0 --disable-filter=true

# kube-apiserver
# 浏览器打开 http://x.x.x.x:8001/debug/pprof/ 查看apiserver的pprof信息
# 获取apiserver的goroutine信息（概要）
curl http://x.x.x.x:8001/debug/pprof/goroutine?debug=1
# 或（详细信息）
curl http://x.x.x.x:8001/debug/pprof/goroutine?debug=2
# TODOTODO

# kubelet
# 获取kubelet指标
curl http://127.0.0.1:8001/api/v1/nodes/node-x/proxy/metrics
# 保持kubelet在线运行，使用pprof分析kubelet，拿到goroutine堆栈
curl http://127.0.0.1:8001/api/v1/nodes/node-x/proxy/debug/pprof/goroutine?debug=2
# 停止kubelet进程，并打印堆栈，特别有助于定位hang住的问题
kill -s SIGQUIT <pid-of-kubelet>
# 或者
kill -SIGABRT <pid-of-kubelet>
# 收集heap信息
wget -O kubelet-heap.out http://127.0.0.1:8001/api/v1/nodes/node-x/proxy/debug/pprof/heap
# 收集profile信息
wget -O kubelet-profile.out http://127.0.0.1:8001/api/v1/nodes/node-x/proxy/debug/pprof/profile

# kubelet健康检查
curl 127.0.0.1:10248/healthz
# 获取更多细节
curl -k https://127.0.0.1:10250/healthz --cacert /etc/kubernetes/keys/ca.pem --cert /etc/kubernetes/keys/kubernetes.pem --key /etc/kubernetes/keys/kubernetes-key.pem
# 或者
curl -k https://127.0.0.1:10250/healthz --cacert /etc/kubernetes/pki/ca.crt --cert /etc/kubernetes/pki/apiserver-kubelet-client.crt --key /etc/kubernetes/pki/apiserver-kubelet-client.key

# kubelet的metrics，其中ca.crt、tls.crt和tls.key从kubeconfig中提取
curl -k https://127.0.0.1:10250/metrics --cacert ca.crt --cert tls.crt --key tls.key

# kubelet “看到”的节点内存实际用量
NODE_IP=10.0.0.123
sudo curl -sk https://${NODE_IP}:10250/metrics/resource --cacert /etc/kubernetes/pki/ca.crt --cert /etc/kubernetes/pki/apiserver-kubelet-client.crt --key /etc/kubernetes/pki/apiserver-kubelet-client.key | grep node_memory_working_set_bytes
```

| 路径                | 说明                |
|-------------------|-------------------|
| /metrics          | kubelet自己的指标      |
| /metrics/cadvisor | 容器监控指标            |
| /metrics/probes   | Pod的Prober指标      |
| /metrics/resource | 节点和Pod的CPU和内存资源开销 |


## kube-apiserver
```bash
# 动态调整kube-apiserver日志级别
curl -X PUT http://127.0.0.1:8001/debug/flags/v -d "4"

# 开启proxy
kubectl proxy --address=0.0.0.0 --disable-filter=true
# 收集heap
wget -O $(hostname)-heap-$(date +"%y%m%d%H%M") http://127.0.0.1:8001/debug/pprof/heap
# 收集goroutine
curl http://127.0.0.1:8001/debug/pprof/goroutine?debug=2 >> $(hostname)-goroutine-debug2-$(date +"%y%m%d%H%M")
# 收集profile
wget -O $(hostname)-profile-$(date +"%y%m%d%H%M") http://127.0.0.1:8001/debug/pprof/profile

# 分析pprof
go tool pprof -http :8080 *-{heap,goroutine-debug2,profile}-*
```

## kubelet
```bash
# 动态调整kubelet日志级别，不用重启服务
NODENAME=hehe
kubectl proxy &
sleep 1s  # 等待proxy端口开始监听
curl -X PUT http://127.0.0.1:8001/api/v1/nodes/${NODENAME}/proxy/debug/flags/v -d "5"

# 收集kubelet堆栈，在/tmp目录查看堆栈文件，该操作不会导致kubelet进程重启
kill -s SIGUSR2 `pidof kubelet`

# 使用kubectl收集
NODENAME=hehe
kubectl get --raw /api/v1/nodes/${NODENAME}/proxy/debug/pprof/heap > kubelet-heap-$NODENAME-$(date +"%Y%m%d_%H%M%S").out
kubectl get --raw /api/v1/nodes/${NODENAME}/proxy/debug/pprof/profile > kubelet-profile-$NODENAME-$(date +"%Y%m%d_%H%M%S").out
# 查看pprof信息
go tool pprof -http :8080 xxx.out

# 节点本地收集kubelet的profile文件
TODO

# 查看kubelet的metrics
NODENAME=hehe
kubectl get --raw /api/v1/nodes/$NODENAME/proxy/metrics | grep go_gc_pauses_seconds_bucket
```

## kube-controller-manager

## kube-scheduler
在日志中，dump出kube-scheduler的内存数据（`Dump of cached NodeInfo`）：
```bash
kill -s SIGUSR2 $(pidof kube-scheduler)
```

主要包括等待调度的Pod队列详情（`Dump of scheduling queue`），以及各节点：
* 节点名
* 已请求资源`Requested Resources`
* 可分配资源`Allocatable Resources`
* 已调度的Pod详情

# 备忘
## k8s版本信息
- [API Removal](https://kubernetes.io/docs/reference/using-api/deprecation-guide/)
- [API废弃策略](https://kubernetes.io/docs/reference/using-api/deprecation-policy/)

## 从源码编译kubernetes时版本信息
`hack/print-workspace-status.sh`

## 修改结构体定义后更新api-rules校验
在修改源码中结构体定义后，需要执行如下命令，更新排除api校验规则的文件`api/api-rules/violation_exceptions.list` ：
```bash
FORCE_HOST_GO=1 make generated_files UPDATE_API_KNOWN_VIOLATIONS=true
```
其中`FORCE_HOST_GO=1`强制使用主机上的go，否则默认使用`.go-version`定义的版本。

## 构建时如何选取version
kubernetes在构建时，根据git获取信息生成version，主要实现在 *kubernetes/hack/lib/version.sh* 中，核心是使用`git describe`：
> KUBE_GIT_VERSION=$("${git[@]}" describe --tags --match='v*' --abbrev=14 "${KUBE_GIT_COMMIT}^{commit}" 2>/dev/null)

再将`KUBE_GIT_VERSION`转成`semantic version`格式。

## StatefulSet无法更新中volumeClaimTemplates的request
* [问题讨论](https://serverfault.com/questions/955293/how-to-increase-disk-size-in-a-stateful-set)
* [社区issue](https://github.com/kubernetes/kubernetes/issues/68737)

## 其它
`kube-controller-manager`的默认配置在`kubernetes/pkg/controller/apis/config/v1alpha1/zz_generated.defaults.go`中`SetDefaults_KubeControllerManagerConfiguration()`设置。
