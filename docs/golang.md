# TOC

<!-- TOC -->
* [TOC](#toc)
* [开发](#开发)
  * [网络编程](#网络编程)
    * [http客户端超时和请求时context超时的区别](#http客户端超时和请求时context超时的区别)
* [常用操作](#常用操作)
  * [避免1.17的编译注释被自动修改](#避免117的编译注释被自动修改)
* [编译构建](#编译构建)
  * [build tag](#build-tag)
    * [用法](#用法)
    * [与](#与)
    * [或](#或)
    * [非](#非)
    * [传tag](#传tag)
  * [buildinfo](#buildinfo)
  * [裁剪可执行文件中mod version信息](#裁剪可执行文件中mod-version信息)
    * [方法一：关闭mod](#方法一关闭mod)
    * [方法二：build时不带mod version](#方法二build时不带mod-version)
  * [通过ldflags在编译阶段设置变量值](#通过ldflags在编译阶段设置变量值)
  * [常用命令](#常用命令)
* [如何Debug Golang程序](#如何debug-golang程序)
  * [打印堆栈](#打印堆栈)
  * [使用devle调试Go程序](#使用devle调试go程序)
  * [使用go tool trace追踪Go程序](#使用go-tool-trace追踪go程序)
  * [使用pprof定位Go程序问题](#使用pprof定位go程序问题)
    * [示例：使用pprof定位kubelet](#示例使用pprof定位kubelet)
  * [golang diagnostics](#golang-diagnostics)
* [Deep Dive系列](#deep-dive系列)
  * [http.Transport中连接池管理](#httptransport中连接池管理)
  * [atomic原子操作](#atomic原子操作)
    * [使用Value替代Bool](#使用value替代bool)
    * [使用Value替代Pointer](#使用value替代pointer)
  * [cgo](#cgo)
* [通过goproxy代理解决package下载问题](#通过goproxy代理解决package下载问题)
* [示例](#示例)
  * [启HTTP服务](#启http服务)
  * [测试cpu性能](#测试cpu性能)
  * [代码实例](#代码实例)
    * [自定义排序](#自定义排序)
    * [在多个地址/端口上监听](#在多个地址端口上监听)
<!-- TOC -->

# 开发
## 网络编程
### http客户端超时和请求时context超时的区别
TODO: [Go http client timeout vs context timeout](https://stackoverflow.com/questions/64129364/go-http-client-timeout-vs-context-timeout)


# 常用操作

## 避免1.17的编译注释被自动修改
```bash
for s in $(git status | grep modified | awk '{print $2}'); do
    c=$(head -n1 $s | grep "^//go:build" -c)
    if [ $c -eq 1 ]; then
        sed -i '1d' $s
    fi
done
```

```bash
# 编译静态链接的可执行文件
CGO_ENABLED=0 go build -o harbor_ui github.com/vmware/harbor/src/ui

# 使用vendor
go build -mod vendor ./pkg/agent
```

# 编译构建
## build tag
### 用法
在待控制的源文件头加：
```
// +build tag_name
```
编译时需指定如下`tag`，才将源文件编进去，具体操作如下：
```
go build -tags tag_name
```
详见 [customizing-go-binaries-with-build-tags](https://www.digitalocean.com/community/tutorials/customizing-go-binaries-with-build-tags)

### 与
```
// +build linux,cgo
```

或者

```
// +build linux
// +build cgo
```

### 或
```
// +build linux darwin
```

### 非
```
// +build !linux
```

### 传tag
```
go build -tags=linux
go build -tags="linux cgo"
go build -tags=linux,cgo
```

**注意**，如下方式会导致前面的tag被覆盖，不能这样使用：
```
go build -tags=linux -tags=cgo
```

## buildinfo
- fix: [cmd/go: do not include module info when -buildinfo=false](https://go-review.googlesource.com/c/go/+/376674)
- issue: [cmd/go: no way to omit package information from binary](https://github.com/golang/go/issues/50501)

## 裁剪可执行文件中mod version信息
### 方法一：关闭mod
```bash
# go build时关闭GO111MODULE
GO111MODULE="off" go build xxx
# 或者
GO111MODULE="off" make xxx
```

### 方法二：build时不带mod version
参见 [go/issues/50501](https://github.com/golang/go/issues/50501) ，已不支持去除mod信息。

## 通过ldflags在编译阶段设置变量值
例如在 *pkg/version/version.go* 中定义有变量：
```golang
var BuildVersion = "xxxx"
```

编译时，通过`-ldflags`设置`BuildVersion`变量值：
```bash
GLDFLAGS="-X ${REPO}/pkg/version.Raw=${VERSION_OVERRIDE} -X ${REPO}/pkg/version.BuildVersion=${BUILD_VERSION}"
go build -ldflags "${GLDFLAGS}" ...
```

## 常用命令
```bash
# 查看exec-binary-file中使用的mod的version
go version -m exec-binary-file
```

# 如何Debug Golang程序

## 打印堆栈
在最佳实践中，Golang程序会监听signal，一旦接收的对应的信号就打印堆栈信息，用于debug。
如下示例摘取自`docker/containerd`：
```go
import (
    "runtime"
)

// DumpStacks dumps the runtime stack.
func dumpStacks() {
	var (
		buf       []byte
		stackSize int
	)
	bufferLen := 16384
	for stackSize == len(buf) {
		buf = make([]byte, bufferLen)
		stackSize = runtime.Stack(buf, true)
		bufferLen *= 2
	}
	buf = buf[:stackSize]
	logrus.Infof("=== BEGIN goroutine stack dump ===\n%s\n=== END goroutine stack dump ===", buf)
}

func setupDumpStacksTrap() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR1)
	go func() {
		for range c {
			dumpStacks()
		}
	}()
}

func main() {
    ...
    setupDumpStacksTrap()
    ...
}
```

## 使用devle调试Go程序
参见 [项目地址](https://github.com/go-delve/delve)。


## 使用go tool trace追踪Go程序
使用`go tool trace`能有效追踪程序执行性能问题、死锁等问题。

TODO

参考资料：
- [Golang 大杀器之跟踪剖析 trace](https://segmentfault.com/a/1190000019736288)


## 使用pprof定位Go程序问题
kube-apiserver集成了pprof工具，可以通过/debug/prof/*获得kube-apiserver的heap、profile等信息：
```bash
# 首先开启代理，会监听 127.0.0.1:8001
kubectl proxy
# 已采集的性能数据，可以启web server访问
go tool pprof -http=0.0.0.0:8088 /path/to/pprof.kube-apiserver.goroutine.001.pb.gz
# 也可以交互式访问
go tool pprof /path/to/pprof.kube-apiserver.goroutine.001.pb.gz

# 当通过web可视化访问时，可能提示“Failed to execute dot. Is Graphviz installed?”，需要安装graphviz
# 命令如下，参见链接 https://graphviz.org/download/
yum install graphviz
# windows从 https://graphviz.org/download/#windows 下载并安装
# 然后设置PATH，将graphviz的bin（默认C:\Program Files\Graphviz\bin）添加到PATH环境变量中

# 内存heap信息
go tool pprof http://127.0.0.1:8001/debug/pprof/heap
# 进入交互界面后，输入top 20查看内存使用前20的函数调用
top 20

# goroutine堆栈信息
go tool pprof http://127.0.0.1:8001/debug/pprof/goroutine
# 进入交互界面，查看“执行数量”前top的goroutine
top
# 查看goroutine调用栈
traces
# 查看代码详情
list
# 获取 goroutine pprof 文件后，直接打开
TODO

# 获取profile文件：
go tool pprof http://127.0.0.1:8001/debug/pprof/profile
# 查看30s的CPU Profile
go tool pprof http://127.0.0.1:8001/debug/pprof/profile?seconds=30

# 当程序里调用 runtime.SetBlockProfileRate 后，查看 goroutine blocking profile
go tool pprof http://127.0.0.1:8001/debug/pprof/block

# 当程序里调用 runtime.SetMutexProfileFraction 后，查看 contended mutexes 锁的持有者
go tool pprof http://127.0.0.1:8001/debug/pprof/mutex

# 获取并分析5秒的Trace追踪信息
wget -O trace.out http://127.0.0.1:8001/debug/pprof/trace?seconds=5
go tool trace trace.out

# 查阅所有profile信息，浏览器打开如下链接：
# http://127.0.0.1:8001/debug/pprof/
```


参考资料：
- https://segmentfault.com/a/1190000039649589
- https://www.kubernetes.org.cn/3119.html
- https://pkg.go.dev/net/http/pprof
- https://lightcone.medium.com/how-to-profile-go-programs-c6c00e8f2ebf
- TODO https://www.huaweicloud.com/articles/760089e5e8665e2397024ce2b9c39871.html
- TODO https://go.dev/blog/pprof
- TODO https://github.com/rsc/benchgraffiti


### 示例：使用pprof定位kubelet
```bash
# master节点上，开启debug代理
kubectl proxy

node=<问题节点>

# 【可选】动态调整kubelet日志级别
curl -X PUT http://127.0.0.1:8001/api/v1/nodes/${node}/proxy/debug/flags/v -d "4"

# 收集pprof
wget -O ${node}-profile-$(date +"%y%m%d%H%M") http://127.0.0.1:8001/api/v1/nodes/${node}/proxy/debug/pprof/profile
wget -O ${node}-heap-$(date +"%y%m%d%H%M") http://127.0.0.1:8001/api/v1/nodes/${node}/proxy/debug/pprof/heap
curl http://127.0.0.1:8001/api/v1/nodes/${node}/proxy/debug/pprof/goroutine?debug=1 >> ${node}-goroutine-debug1-$(date +"%y%m%d%H%M")
curl http://127.0.0.1:8001/api/v1/nodes/${node}/proxy/debug/pprof/goroutine?debug=2 >> ${node}-goroutine-debug2-$(date +"%y%m%d%H%M")

# 打开pprof
go tool pprof -http :8080 ./<heap 文件>
go tool pprof -http :8080 ./<profile 文件>
```

## golang diagnostics
TODO: https://golang.org/doc/diagnostics

# Deep Dive系列
## http.Transport中连接池管理
`http.Transport`的`getConn()`方法，从连接池中获取空闲连接，或新建一个连接。

## atomic原子操作
TODO:
- [Go 语言标准库中 atomic.Value 的前世今生](https://blog.betacat.io/post/golang-atomic-value-exploration/)

### 使用Value替代Bool
```golang
...
showHidden          atomic.Value
...
func ShouldShowHidden() bool {
	return showHidden.Load() != nil && showHidden.Load().(bool)
}
```

### 使用Value替代Pointer
```golang
...
cache atomic.Value
...

var resettedHint bool = true

// Reset
cache.Store(&resettedHint)

// Main process logic
cacheLoad, ok := cache.Load().(*cachedGroupList)
if ok {
	return cacheLoad
} else {
	cached := &cachedGroupList{
		cachedResponse:     response,
		cachedResponseETag: etag,
	}
	cache.Store(cached)
	return cached
}
```

## cgo
TODO: https://chai2010.cn/advanced-go-programming-book/ch2-cgo/ch2-02-basic.html

# 通过goproxy代理解决package下载问题
```bash
go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.cn,direct

# 设置不走 proxy 的私有仓库，多个用逗号相隔（可选）
go env -w GOPRIVATE=*.corp.example.com

# 设置不走 proxy 的私有组织（可选）
go env -w GOPRIVATE=example.com/org_name
```
参见[goproxy官网](https://goproxy.io/zh/)


# 示例

## 启HTTP服务
`http.go`文件内容如下：
```golang
package main

import (
        "net/http"
)

func main() {
        http.Handle("/", http.FileServer(http.Dir("./")))
        http.ListenAndServe(":34567", nil)
}
```
执行命令`go run http.go`启动服务。

## 测试cpu性能
```golang
package main

import "math/rand"

func main() {
        var c int
        for i := 0; i < 1024 * 1024 * 1024; i++ {
                c = rand.Int() * rand.Int()
                c = c * rand.Int()
        }
}
```

## 代码实例

### 自定义排序
```golang
// 自定义排序方式
sort.Sort(byCreationTimestamp(terminatedPods))
...
// byCreationTimestamp sorts a list by creation timestamp, using their names as a tie breaker.
type byCreationTimestamp []*v1.Pod

func (o byCreationTimestamp) Len() int      { return len(o) }
func (o byCreationTimestamp) Swap(i, j int) { o[i], o[j] = o[j], o[i] }

func (o byCreationTimestamp) Less(i, j int) bool {
	if o[i].CreationTimestamp.Equal(&o[j].CreationTimestamp) {
		return o[i].Name < o[j].Name
	}
	return o[i].CreationTimestamp.Before(&o[j].CreationTimestamp)
}
```

### 在多个地址/端口上监听
```golang
package main

import (
	"net/http"
)

func index(rw http.ResponseWriter, req *http.Request) {
	rw.Write([]byte("hello world"))
}

func main() {
	http.HandleFunc("/", index)
	go http.ListenAndServe("127.0.0.1:1555", nil)
	go http.ListenAndServe("127.0.0.1:1666", nil)
	select {}
}
```