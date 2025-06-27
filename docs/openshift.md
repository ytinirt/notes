# TOC

<!-- TOC -->
* [TOC](#toc)
* [Deep Dive](#deep-dive)
  * [SCC](#scc)
    * [使用oc adm policy设置scc权限的注意事项](#使用oc-adm-policy设置scc权限的注意事项)
    * [代码方式为sa设置scc权限](#代码方式为sa设置scc权限)
    * [“我”是否有这个操作权限](#我是否有这个操作权限)
    * [“谁”有这个操作权限](#谁有这个操作权限)
* [常用操作](#常用操作)
  * [日志收集must-gather](#日志收集must-gather)
  * [Operator关键行为](#operator关键行为)
    * [rollout新版本](#rollout新版本)
  * [配置审计日志策略](#配置审计日志策略)
  * [检查被废弃API的使用情况](#检查被废弃api的使用情况)
  * [获取用户认证Token](#获取用户认证token)
    * [使用whoami获取Token](#使用whoami获取token)
    * [获取OAuth用户的Token](#获取oauth用户的token)
    * [从ServiceAccount中获取Token](#从serviceaccount中获取token)
  * [更新](#更新)
    * [强制更新](#强制更新)
  * [修改节点kubelet配置](#修改节点kubelet配置)
  * [让cvo不要调谐资源](#让cvo不要调谐资源)
  * [让cvo删除资源](#让cvo删除资源)
  * [强制rollout组件](#强制rollout组件)
* [测试](#测试)
  * [执行内容查询](#执行内容查询)
  * [UT](#ut)
  * [IT](#it)
  * [组件e2e](#组件e2e)
  * [版本e2e](#版本e2e)
* [OpenShift3 and OKD](#openshift3-and-okd)
  * [常用操作](#常用操作-1)
  * [官方yum源](#官方yum源)
  * [OpenShift 3.x DNS介绍](#openshift-3x-dns介绍)
  * [深入OpenShift SDN网络](#深入openshift-sdn网络)
<!-- TOC -->

# Deep Dive
## SCC
SCC基于admission control准入检查机制实现。
代码详见 [openshift/apiserver-library-go](https://github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints) 。

OpenShift中预置的SCC：
```
# oc get scc
NAME         PRIV    CAPS            SELINUX     RUNASUSER          FSGROUP     SUPGROUP    PRIORITY     READONLYROOTFS   VOLUMES
anyuid       false   <no value>      MustRunAs   RunAsAny           RunAsAny    RunAsAny    10           false            ["configMap","downwardAPI","emptyDir","persistentVolumeClaim","projected","secret"]
hostaccess   false   <no value>      MustRunAs   MustRunAsRange     MustRunAs   RunAsAny    <no value>   false            ["configMap","downwardAPI","emptyDir","hostPath","persistentVolumeClaim","projected","secret"]
nonroot      false   <no value>      MustRunAs   MustRunAsNonRoot   RunAsAny    RunAsAny    <no value>   false            ["configMap","downwardAPI","emptyDir","persistentVolumeClaim","projected","secret"]
...
privileged   true    ["*"]           RunAsAny    RunAsAny           RunAsAny    RunAsAny    <no value>   false            ["*"]
restricted   false   <no value>      MustRunAs   MustRunAsRange     MustRunAs   RunAsAny    <no value>   false            ["configMap","downwardAPI","emptyDir","persistentVolumeClaim","projected","secret"]
```
这些SCC由`kube-apiserver-operator`设置，详见实现`cluster-kube-apiserver-operator/bindata/bootkube/scc-manifests` 。

预置的SCC中，*anyuid*具有最高优先级（PRIORITY），因此当用户有 *use scc/anyuid* 权限时（`oc adm policy who-can use securitycontextconstraints/anyuid`），会优先匹配到*anyuid*。

除*anyuid*外，其余预置scc的优先级一样。
这时按照资源/权限限制由**强**到**弱**排序，依次为pod匹配scc，按照*restricted*到*privileged*的排序。
实现详见`openshift/apiserver-library-go/pkg/securitycontextconstraints/sccadmission/admission.go`中`computeSecurityContext()`。

注意，在为pod匹配scc时，需要创建pod的用户（例如deployment的pod最终由system:serviceaccount:kube-system:replicaset-controller创建）或者pod里的ServiceAccount具备*use*该scc资源的权限，否则跳过。
这表明了在为sa赋予scc权限时，实际上就是为sa创建ClusterRoleBinding，让其能够访问scc/xxx资源。

根据scc为pod和容器设置securityContext时，mcs标签、fsGroup、uid等信息从命名空间的注解取得，例如：
```
openshift.io/sa.scc.mcs: s0:c24,c9
openshift.io/sa.scc.supplemental-groups: 1000570000/10000
openshift.io/sa.scc.uid-range: 1000570000/10000
```

上述注解由*cluster-policy-controller*设置，其以容器方式运行在OpenShift的*pod/kube-controller-manager*中。扩展的控制器包括：
```
var ControllerInitializers = map[string]InitFunc{
	"openshift.io/namespace-security-allocation":      RunNamespaceSecurityAllocationController,
	"openshift.io/resourcequota":                      RunResourceQuotaManager,
	"openshift.io/cluster-quota-reconciliation":       RunClusterQuotaReconciliationController,
	"openshift.io/cluster-csr-approver":               RunCSRApproverController,
	"openshift.io/podsecurity-admission-label-syncer": runPodSecurityAdmissionLabelSynchronizationController,
}
```
代码详见 [cluster-policy-controller](https://github.com/openshift/cluster-policy-controller) 。

### 使用oc adm policy设置scc权限的注意事项
OpenShift的SCC实际上基于RBAC实现。

需要注意如下两条命令的区别：
1. `oc adm policy add-scc-to-user privileged -n hehe -z default`
2. `oc adm policy add-scc-to-user privileged system:serviceaccount:hehe:default`

上述命令1，创建`RoleBinding`，将`Privileged`赋予了hehe命名空间下的sa/default后得到如下结果：
```bash
# oc auth can-i --as=system:serviceaccount:hehe:default use scc/privileged
no
# oc auth can-i --as=system:serviceaccount:hehe:default use scc/privileged -n hehe
yes
```

上述命令2，创建`ClusterRoleBinding`，将`Privileged`赋予了hehe命名空间下的sa/default后得到如下结果：
```bash
# oc auth can-i --as=system:serviceaccount:hehe:default use scc/privileged
yes
# oc auth can-i --as=system:serviceaccount:hehe:default use scc/privileged -n hehe
yes
```

### 代码方式为sa设置scc权限
根据scc实现原理，便可以通过创建`ClusterRoleBinding`为sa指定scc权限
```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: <自定义一个名字>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:openshift:scc:privileged
subjects:
- kind: ServiceAccount
  name: node-problem-detector
  namespace: openshift-npd-system
```

### “我”是否有这个操作权限
```bash
oc auth can-i --as=system:serviceaccount:default:user use scc/privileged
oc auth can-i --as=system:serviceaccount:default:user use scc/anyuid
```

### “谁”有这个操作权限
```bash
oc adm policy who-can use securitycontextconstraints/privileged
oc adm policy who-can use securitycontextconstraints/anyuid
```

# 常用操作

## 日志收集must-gather
使用must-gather收集审计日志：
```bash
oc adm must-gather -- /usr/bin/gather_audit_logs
```

具体的，会拉起一个临时pod（使用must-gather镜像），这个pod里执行日志收集脚本。上面的例子中，就会执行`/usr/bin/gather_audit_logs`这个脚本。
脚本中大量使用oc/kubectl命令查询集群信息和收集日志，因此会创建临时clusterRoleBinding，为pod使用的sa临时指定cluster-admin权限。

## Operator关键行为
### rollout新版本
```bash
oc logs -n openshift-kube-apiserver-operator kube-apiserver-operator-xxx | grep triggered
```

## 配置审计日志策略
[TODO](https://access.redhat.com/documentation/en-us/openshift_container_platform/4.10/html/security_and_compliance/audit-log-policy-config)

## 检查被废弃API的使用情况
参见[Navigating Kubernetes API deprecations and removals](https://access.redhat.com/articles/6955985) :
```bash
# 过滤出会被废弃的API
oc get apirequestcounts \
    -o jsonpath='{range .items[?(@.status.removedInRelease!="")]}{.status.removedInRelease}{"\t"}{.status.requestCount}{"\t"}{.metadata.name}{"\n"}{end}'

# 过滤出谁在访问被废弃的API
oc get apirequestcounts ingresses.v1beta1.networking.k8s.io \
  -o jsonpath='{range .status.last24h..byUser[*]}{..byVerb[*].verb}{","}{.username}{","}{.userAgent}{"\n"}{end}' \
  | sort -k 2 -t, -u | column -t -s, -NVERBS,USERNAME,USERAGENT
```

注意，如下用户可忽略，它们是内建用户、会遍历处理所有资源：
- `system:serviceaccount:kube-system:generic-garbage-collector` 和 `system:serviceaccount:kube-system:namespace-controller` ，它们会遍历访问所有资源
- `system:kube-controller-manager` 和 `system:cluster-policy-controller` ，它们会遍历处理所有资源


## 获取用户认证Token
### 使用whoami获取Token
```bash
USER=user
PASSWORD=passwd
oc login -u ${USER} -p ${PASSWORD}
oc whoami -t
```

### 获取OAuth用户的Token
```bash
USER=user
PASSWORD=passwd
OAUTH=$(oc get route oauth-openshift -n openshift-authentication -ojson | jq -r .spec.host)
curl -sik "https://${OAUTH}/oauth/authorize?response_type=token&client_id=openshift-challenging-client" --user ${USER}:${PASSWORD} | grep -oP "access_token=\K[^&]*"
```

### 从ServiceAccount中获取Token
```bash
SA=user
NS=test
API=$(oc whoami --show-server)
TOKEN=$(oc serviceaccounts get-token ${SA} -n ${NS})
# 通过TOKEN查找user
oc get user '~' --token=${TOKEN}
curl -H "Authorization: Bearer ${TOKEN}" -X GET -k ${API}/apis
```

```bash
## 修改kube-controller-manager配置
# 编辑kubecontrollermanager.operator.openshift.io/cluster，
# 参考observedConfig，增加unsupportedConfigOverrides字段，在extendedArguments中指定希望配置的参数
spec:
  observedConfig:
    extendedArguments:
      cluster-cidr:
      - 10.0.0.0/14
  unsupportedConfigOverrides:
    extendedArguments:
      node-monitor-grace-period:
      - 15s
  useMoreSecureServiceCA: true


## 查询监控指标
secretname=$(kubectl get serviceaccount --namespace=openshift-monitoring prometheus-k8s -o jsonpath='{.secrets[1].name}')
BRIDGE_K8S_AUTH_BEARER_TOKEN=$(kubectl get secret "$secretname" --namespace=openshift-monitoring -o template --template='{{.data.token}}' | base64 --decode)
THANOS_QUERIER_SVC=$(kubectl get svc -n openshift-monitoring thanos-querier --no-headers | awk '{print $3}')
PROM_QL='ALERTS{alertname!~"Watchdog|AlertmanagerReceiversNotConfigured|PrometheusRemoteWriteDesiredShards",alertstate="firing",severity!="info"}'

curl -k -H "Authorization: Bearer $BRIDGE_K8S_AUTH_BEARER_TOKEN" \
"https://$THANOS_QUERIER_SVC:9091/api/v1/query" \
--data-urlencode "query=$PROM_QL"


## 新增pullSecret
# 编辑 /var/lib/kubelet/config.json，在文件中增加auth
vi /var/lib/kubelet/config.json
# 重启crio服务
systemctl restart crio


## 使用oc命令执行容器镜像mirror操作
oc image mirror -a /var/lib/kubelet/config.json quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:ae92a919cb6da4d1a5d832f8bc486ae92e55bf3814ebab94bf4baa4c4bcde85d image.ytinirt.cn/zhaoyao/ocp4
# 如果image.ytinirt.cn没有访问权限，需要把该仓库的auth追加到/var/lib/kubelet/config.json
# 如果image.ytinirt.cn的CA不是权威的，可以将其CA放到 /etc/pki/ca-trust/source/anchors 目录下，并执行 update-ca-trust extract


## 使用podman操作容器镜像
# 镜像导出，导出多个镜像时注意增加 -m 标识
sudo podman save -m quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:8c8813c quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:a705303fa | gzip > hehe.tar.gz


## TODOTODO: podman inspect vs podman manifest inspect
sudo podman manifest inspect quay.io/openshift-release-dev/ocp-release@sha256:dd71b3cd08ce1e859e0e740a585827c9caa1341819d1121d92879873a127f5e2
sudo podman inspect quay.io/openshift-release-dev/ocp-release@sha256:dd71b3cd08ce1e859e0e740a585827c9caa1341819d1121d92879873a127f5e2
sudo podman manifest inspect  quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:ae92a919cb6da4d1a5d832f8bc486ae92e55bf3814ebab94bf4baa4c4bcde85d --log-level=debug


## 在OpenShift节点上启调试debug容器
podman run --network=host -it centos bash


## 强制跳过machine-config-operator对节点的mc检查
# 在希望跳过的节点上执行
touch /run/machine-config-daemon-force


## 节点后台直接下载容器镜像
# 配置代理，如果需要
export https_proxy=http://127.0.0.1:8080/
export http_proxy=http://127.0.0.1:8080/
# 拿kubelet使用的认证信息，去下载容器镜像
podman pull --authfile /v/var/lib/kubelet/config.json quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:f5628b30aa047fe32cba9308c70c581f7d9812f40a3e651a84f0532af184bfd2


## 直接操作ETCD数据
# 切换为root用户，并执行如下命令
source /etc/kubernetes/static-pod-resources/etcd-certs/configmaps/etcd-scripts/etcd.env
source /etc/kubernetes/static-pod-resources/etcd-certs/configmaps/etcd-scripts/etcd-common-tools
dl_etcdctl
export ETCDCTL_CERT=/etc/kubernetes/static-pod-resources/etcd-certs/secrets/etcd-all-certs/etcd-peer-master0.crt
export ETCDCTL_KEY=/etc/kubernetes/static-pod-resources/etcd-certs/secrets/etcd-all-certs/etcd-peer-master0.key
export ETCDCTL_CACERT=/etc/kubernetes/static-pod-resources/etcd-certs/configmaps/etcd-serving-ca/ca-bundle.crt
etcdctl ...


## 调用OSUS服务，获取graph的示例：
curl --silent --header 'Accept:application/json' 'https://api.openshift.com/api/upgrades_info/v1/graph?arch=amd64&channel=stable-4.2'


## 对接使用htpasswd IDP
# 创建用户名和密码文件
htpasswd -bB users.htpasswd <username> <password>
# 创建secret
kubectl create secret generic htpass-secret --from-file=htpasswd=users.htpasswd -n openshift-config
# 配置OAuth对接htpasswd IDP
cat <<EOF | kubectl apply -f -
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:
  - name: htpasswd_provider
    mappingMethod: claim
    type: HTPasswd
    htpasswd:
      fileData:
        name: htpass-secret
EOF
# 当用户首次登录时，会新建 user 和 identity 资源实例
# 给用户赋予集群管理员权限，其中 cluster-admin 是预置的 clusterRole
oc adm policy add-cluster-role-to-user cluster-admin zhaoyao


## 对接使用htpasswd IDP，更新用户
# 获取当前htpasswd用户和密码文件
oc get secret htpass-secret -ojsonpath={.data.htpasswd} -n openshift-config | base64 --decode > users.htpasswd
# 添加新用户
htpasswd -bB users.htpasswd <username> <password>
# 删除老用户，注意，后续需要同步删除对应的 user 和 identity 资源实例
htpasswd -D users.htpasswd <username>
# 使配置生效
oc create secret generic htpass-secret --from-file=htpasswd=users.htpasswd --dry-run=client -o yaml -n openshift-config | oc replace -f -


## 查看审计日志
oc adm node-logs --role=master --path=kube-apiserver
oc adm node-logs master0 --path=kube-apiserver/audit.log
## 收集audit审计日志
oc adm must-gather --dest-dir /path/to/audit/logs/dir/ -- /usr/bin/gather_audit_logs


## 查看节点上服务日志
oc adm node-logs <node_name> -u crio
oc adm node-logs <node_name> -u kubelet


## 获取集群所有资源对象，这些资源对象由CVO创建管理
# 获取当前版本的update image，实际上其也是cluster-version-operator pod使用的容器镜像
oc get clusterversion -o jsonpath='{.status.desired.image}{"\n"}' version
# 获取CVO管理对象的列表
oc adm release extract --from=quay.io/openshift-release-dev/ocp-release@sha256:1935b6c8277e351550bd7bfcc4d5df7c4ba0f7a90165c022e2ffbe789b15574a --to=release-image
# release-metadata文件携带版本元数据
# image-references文件携带OpenShift集群需要的容器镜像
ls release-image

## 直接提取版本镜像release image
$ mkdir /tmp/release
$ oc image extract quay.io/openshift-release-dev/ocp-release:4.5.1-x86_64 --path /:/tmp/release


## 让Operator/资源对象不被CVO管理，此后就能随便edit资源对象了
# 查看当前的override信息
oc get -o json clusterversion version | jq .spec.overrides
# 为了向override中增加表项配置，需要给 clusterversion/version 打 patch
# 新建.spec.overrides
cat <<EOF >version-patch-first-override.yaml
- op: add
  path: /spec/overrides
  value:
  - kind: Deployment
    group: apps
    name: network-operator
    namespace: openshift-network-operator
    unmanaged: true
EOF
# 新增一项override
cat <<EOF >version-patch-add-override.yaml
- op: add
  path: /spec/overrides/-
  value:
    kind: Deployment
    group: apps
    name: network-operator
    namespace: openshift-network-operator
    unmanaged: true
EOF
# 执行patch
oc patch clusterversion version --type json -p "$(cat version-patch.yaml)"
## 也可以直接停掉CVO
oc scale --replicas 0 -n openshift-cluster-version deployments/cluster-version-operator

```

## 更新
### 强制更新
```bash
oc adm upgrade --to-image=release-image@sha256:xxx --force --allow-explicit-upgrade
```

## 修改节点kubelet配置
通过`kubeletConfig`修改节点kubelet配置：
```yaml
apiVersion: machineconfiguration.openshift.io/v1
kind: KubeletConfig
metadata:
  name: set-node-lease-duration-worker
spec:
  machineConfigPoolSelector:
    matchLabels:
      pools.operator.machineconfiguration.openshift.io/worker: ""
  kubeletConfig:
    nodeLeaseDurationSeconds: 15
```

## 让cvo不要调谐资源
```bash
# 当新增override项
cat <<EOF >patch.yaml
- op: add
  path: /spec/overrides
  value:
  - kind: Deployment
    group: apps
    name: foo
    namespace: bar
    unmanaged: true
EOF

# 当更新override项
cat <<EOF >patch.yaml
- op: add
  path: /spec/overrides/-
  value:
    kind: Deployment
    group: apps
    name: foo
    namespace: bar
    unmanaged: true
EOF

# 给clusterversion打patch
oc patch clusterversion version --type json -p "$(cat patch.yaml)"
```

## 让cvo删除资源
manifests中yaml增加注解`release.openshift.io/delete: "true"`

## 强制rollout组件
```bash
kubectl patch kubeapiserver cluster -p='{"spec": {"forceRedeploymentReason": "recovery-'"$( date --rfc-3339=ns )"'"}}' --type=merge
```

# 测试
## 执行内容查询
[链接](https://steps.ci.openshift.org/search)

## UT

## IT

## 组件e2e

## 版本e2e


# OpenShift3 and OKD

## 常用操作

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
# 或跳过服务端证书校验
oc login https://vip.cluster.local:8443 -u system:admin --insecure-skip-tls-verify

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



## 官方yum源

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


## OpenShift 3.x DNS介绍
代码 `origin/pkg/dns/serviceresolver.go <Records><ReverseRecord>` 中实现skydns后端接口，用于域名（svc）到IP（clusterIP）的转换。

宿主机上运行的dnsmasq服务配置见 `/etc/dnsmasq.d/origin-dns.conf` ：
1. controller（master）节点上运行master-api，监听`0.0.0.0:8053`端口，数据来自apiserver。
2. node节点上运行skydns（同master类似，直接built-in skydns），监听`127.0.0.1:53`端口，数据同样来自apiserver，`pkg/cmd/server/start/start_allinone.go:250`
3. node节点宿主机上运行dnsmasq，监听除lo口外所有接口的:53端口。后端信息来自2。

宿主机上，对dns解析请求抓包：
```bash
tcpdump -i lo port 53 -nnl
```
虽然`/etc/resolve.conf`中nameserver配置为集群网卡IP地址，但tcpdump指定抓取集群网卡时并不能抓到dns解析的报文。



## 深入OpenShift SDN网络
参考资料[理解OpenShift（3）：网络之 SDN](https://www.cnblogs.com/sammyliu/p/10064450.html)

参考资料中，流程图各步骤说明：
1. cri，docker_sandbox，dockershim，执行实体origin-node
2. docker直接创建容器
3. cni pluginmanager调用openshift-sdn插件，执行实体origin-node，可执行文件openshift-sdn在/opt/cni/bin目录下
4. 请求发往cni-server，执行实体openshift-sdn pod
5. 调用ipam插件host-local（详见pkg/network/node/pod.go:497），获取ip地址和路由信息，并将这些信息直接返回给openshift-sdn插件，然后转第8步
6. 详见pkg/network/node/pod.go:497，调用m.ovs.SetUpPod(req.SandboxID, req.HostVeth, podIP, vnid)
7. 详见pkg/network/node/ovscontroller.go:267
8. openshift-sdn插件调用ip.SetHWAddrByIP和ipam.ConfigureIface设置ip地址和路由信息

各节点subnet信息（类似flanneld在etcd中保存的信息/coreos.com/network）在：
```bash
[root@op-m ~]# etcdctl3 get /openshift.io/registry --prefix --keys-only
/openshift.io/registry/sdnnetworks/default
/openshift.io/registry/sdnsubnets/op-m
/openshift.io/registry/sdnsubnets/op-s1
/openshift.io/registry/sdnsubnets/op-s2

[root@op-m ~]# etcdctl3 get /openshift.io/registry/sdnnetworks/default | strings
/openshift.io/registry/sdnnetworks/default
network.openshift.io/v1
ClusterNetwork
default
*$bc235484-08f0-11e9-9f1d-0cda411d819b2
10.101.0.0/16
10.100.0.0/16*
redhat/openshift-ovs-subnet2
10.101.0.0/16
[root@op-m ~]# etcdctl3 get /openshift.io/registry/sdnsubnets/op-m | strings
/openshift.io/registry/sdnsubnets/op-m
network.openshift.io/v1
HostSubnet
op-m
*$bca6bebb-08f0-11e9-9f1d-0cda411d819b2
!pod.network.openshift.io/node-uid
$b787a6f2-08f0-11e9-9f1d-0cda411d819bz
op-m
172.25.18.233"
10.101.2.0/23
```
openshift SDN根据上述信息配置各node的subnet。
openshift SDN cni-server的运行目录：/run/openshift-sdn

node上kubelet服务配置`/usr/bin/hyperkube kubelet --network-plugin=cni`
```bash
[root@slim-m-18-233 ~]# cat /etc/cni/net.d/80-openshift-network.conf
{
"cniVersion": "0.2.0",
"name": "openshift-sdn",
"type": "openshift-sdn"
}
[root@slim-m-18-233 bin]# pwd
/opt/cni/bin
[root@slim-m-18-233 bin]# ls
host-local loopback openshift-sdn
```

openshift-sdn插件：
1. 通过IPAM获取IP地址并根据subnet地址生成默认添加的路由
2. 设置OVS（ovs-vsctl将infra容器主机端虚拟网卡加入br0，ovs-ofctl设置流表规则）

本节点网络信息位置`/var/lib/cni/networks/openshift-sdn`，例如
```bash
[root@xu openshift-sdn]# cat 10.101.2.92
1cc6a193e9ea4320e0f6282d4eaa6701e12fa21ff361d720c03f6e1fe9d1b324
```

附使用IPAM插件host-local分配IP地址的示例：
```bash
echo '{ "cniVersion": "0.3.1", "name": "examplenet", "ipam": { "type": "host-local", "ranges": [ [{"subnet": "203.0.113.0/24"}], [{"subnet": "2001:db8:1::/64"}]], "dataDir": "/tmp/cni-example"  } }' | CI_COMMAND=ADD CNI_CONTAINERID=example CNI_NETNS=/dev/null CNI_IFNAME=dummy0 CNI_PATH=. ./host-local
```

进入openshift-sdn命名空间任一pod，使用如下命令查看信息：
```bash
ovs-vsctl show
ovs-ofctl -O OpenFlow13 dump-flows br0
ovs-ofctl -O OpenFlow13 dump-tables br0
ovs-ofctl -O OpenFlow13 dump-ports br0
ovs-ofctl -O OpenFlow13 show br0
nsenter -t <容器的PID> -n ip link
iptables -t nat -s
```

为Pod设置默认路由的地方：
```golang
// pkg/network/node/pod.go:112

// Generates a CNI IPAM config from a given node cluster and local subnet that
// CNI 'host-local' IPAM plugin will use to create an IP address lease for the
// container
func getIPAMConfig(clusterNetworks []common.ClusterNetwork, localSubnet string) ([]byte, error)

```


