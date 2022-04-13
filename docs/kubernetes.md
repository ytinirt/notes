# TOC

<!--ts-->
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
      * [自定义调度器](#自定义调度器)
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
      * [Kubernetes用户](#kubernetes用户)
         * [服务账号Service Account](#服务账号service-account)
         * [证书用户User](#证书用户user)
            * [如何创建一个证书用户](#如何创建一个证书用户)
   * [操作实例](#操作实例)
      * [从secret中获取证书信息](#从secret中获取证书信息)
      * [debug和问题解决](#debug和问题解决)
      * [常见操作](#常见操作)
      * [客户端访问集群时context配置](#客户端访问集群时context配置)
      * [ConfigMap使用](#configmap使用)
      * [日志相关配置](#日志相关配置)
      * [提升集群HA性能](#提升集群ha性能)
      * [强制删除Pod](#强制删除pod)
      * [Pod中获取PodIP的方法](#pod中获取podip的方法)
      * [emptyDir在宿主机上的路径](#emptydir在宿主机上的路径)
      * [FC存储多路径的PV配置](#fc存储多路径的pv配置)
      * [编译kubelet](#编译kubelet)

<!-- Added by: root, at: Wed Apr 13 23:28:01 CST 2022 -->

<!--te-->


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
## Kubernetes用户
### 服务账号Service Account
### 证书用户User
#### 如何创建一个证书用户
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


# 操作实例

## 从secret中获取证书信息
```bash
function b642cert {
  local b64=$1
  echo $b64 | base64 -d | openssl x509 -noout -text
}
```

## debug和问题解决
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
# 保持kubelet在线运行，使用pprof分析kubelet，拿到goroutine堆栈
curl http://localhost:8001/api/v1/proxy/nodes/node-x/debug/pprof/goroutine?debug=2
# 或者
curl http://127.0.0.1:8001/api/v1/nodes/node-x/proxy/debug/pprof/goroutine?debug=2
# 停止kubelet进程，并打印堆栈，特别有助于定位hang住的问题
kill -s SIGQUIT <pid-of-kubelet>
# 或者
kill -SIGABRT <pid-of-kubelet>
# 收集heap信息
wget -O kubelet-heap.out http://127.0.0.1:8001/api/v1/nodes/node-x/proxy/debug/pprof/heap

# kubelet健康检查
curl 127.0.0.1:10248/healthz
# 获取更多细节
curl -k https://127.0.0.1:10250/healthz --cacert /etc/kubernetes/keys/ca.pem --cert /etc/kubernetes/keys/kubernetes.pem --key /etc/kubernetes/keys/kubernetes-key.pem


```

## 常见操作

```bash
function man_pull {
    local ns=$1
    local pod=$2

    for i in $(kubectl get pod -n ${ns} ${pod} -o json | jq .spec.containers[].image -r | sort | uniq); do
        podman pull $i
    done
}

# 定制输出
kubectl get pod --sort-by=.status.startTime -o=custom-columns=name:.metadata.name,startTime:.status.startTime

# 以创建时间排序
kubectl get secret -A --sort-by .metadata.creationTimestamp

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
# 查看所有Pod
kubectl get pod | grep -v NAME | awk '{print $1}'      
# 查看Pod的运行状态
kubectl get pod ceportalrc-n5sqd -o template --template={{.status.phase}}          
# 查看Node的操作系统信息
kubectl get node 172.25.18.24 -o template --template={{.status.nodeInfo.osImage}}  
# 查看容器的log
kubectl logs --namespace="kube-system" kube-dns-v17.1-rc1-27sj0 kubedns  
kubectl drain ${node} --delete-local-data --ignore-daemonsets --force
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

# 遍历所有pod
for n_p in $(kubectl get pod -A | sed 1d | awk '{print $1":"$2}'); do
    n=$(echo $n_p | cut -d: -f1)
    p=$(echo $n_p | cut -d: -f2)
    echo $n  $p
    kubectl get pod -n $n $p -o json | jq .spec.containers[].imagePullPolicy -r 2>/dev/null
    kubectl get pod -n $n $p -o json | jq .spec.initContainers[].imagePullPolicy -r 2>/dev/null
    echo
done

# 遍历所有工作负载
WorkLoads="ds deploy rc sts"
for wl in $(echo $WorkLoads); do
    echo "============== $wl =============="
    for n_i in $(kubectl get $wl -A | sed 1d | awk '{print $1":"$2}'); do
        n=$(echo $n_i | cut -d: -f1)
        i=$(echo $n_i | cut -d: -f2)
        echo $n $i : $(kubectl get $wl -n $n $i -o json | jq .spec.template.spec.containers[].imagePullPolicy -r 2>/dev/null) $(kubectl get $wl -n $n $i -o json | jq .spec.template.spec.initContainers[].imagePullPolicy -r 2>/dev/null)
    done
done

# 遍历一个命名空间下所有资源
kubectl api-resources --verbs=list --namespaced -o name \
  | xargs -n 1 kubectl get --show-kind --ignore-not-found -n ${NAMESPACE}

# 设置默认StorageClass
kubectl patch storageclass gold -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'

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

## emptyDir在宿主机上的路径

```bash
/var/lib/kubelet/pods/<pod uuid>/volumes/kubernetes.io~empty-dir
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