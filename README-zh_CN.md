# KubeUser

[![Latest Release](https://img.shields.io/github/v/release/openkube-hub/KubeUser?label=latest%20release&sort=semver)](https://github.com/openkube-hub/KubeUser/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/openkube-hub/KubeUser)](https://goreportcard.com/report/github.com/openkube-hub/KubeUser)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Tests](https://github.com/openkube-hub/KubeUser/actions/workflows/test.yml/badge.svg)](https://github.com/openkube-hub/KubeUser/actions/workflows/test.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/openkube-hub/KubeUser)](./go.mod)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/kubeuser)](https://artifacthub.io/packages/search?repo=kubeuser)

[English](./README.md) | 简体中文

KubeUser 是一种 Kubernetes 原生的方式,用于以声明式方法管理用户、证书、RBAC 以及 kubeconfig —— 无需运行外部身份提供商(IdP)。

---

## 概述

管理 Kubernetes 访问权限通常需要手动创建 kubeconfig、处理证书,并持续维护 RBAC 的一致性。这种方式容易出错、难以审计,也不利于 GitOps 工作流。

KubeUser 通过自定义资源(CRD)以声明式方式管理 Kubernetes 用户来解决上述问题。它会自动生成并轮换证书、下发 RBAC 绑定,并使用原生 Kubernetes API 生成开箱即用的 kubeconfig。

**面向对象:** 自建集群 —— 裸金属、kubeadm、k3s/RKE2/Talos、边缘站点,以及气隙(air-gapped)与离线隔离环境 —— 希望获得 Kubernetes 原生、对 GitOps 友好的访问控制,而不必运行 IAM 或 OIDC 体系。KubeUser 所依赖的一切(CSR API、Secret、RBAC)都在集群内部,因此证书签发与轮换无需任何出网流量。KubeUser **不是** 企业级身份提供商的替代品。

> **安装前请注意:** KubeUser 需要集群提供能够签发 `client auth`(客户端认证)证书的 signer。原生及自建发行版均满足该条件,但 **Amazon EKS 不满足** —— 其 signer 不支持客户端证书签发。在托管集群上请先执行
> [预检脚本](docs/cluster-compatibility.md#preflight-check),详见
> [集群兼容性](docs/cluster-compatibility.md)。

### 架构

```
   ┌──────────────┐
   │   User CR    │   kubectl apply -f user.yaml
   └──────┬───────┘
          │
          ▼
   ┌──────────────────────────┐
   │       准入 Webhook        │   TLS 证书由 cert-manager 签发
   │   • Mutating (默认值)     │
   │   • Validating (规则校验) │
   └──────┬───────────────────┘
          │
          ▼
   ┌──────────────────────────┐
   │     User 控制器           │   Reconcile 循环
   │       (Reconciler)       │
   └──┬─────────┬──────────┬──┘
      │         │          │
      ▼         ▼          ▼
   ┌──────┐ ┌─────────┐ ┌────────────┐
   │ CSR  │ │ Secrets │ │   RBAC     │
   │ API  │ │  key +  │ │  Role &    │
   │      │ │ kubecfg │ │  Cluster   │
   │签发   │ │         │ │  Bindings  │
   └──────┘ └─────────┘ └────────────┘
```

---

## 快速开始

在通过 [预检脚本](docs/cluster-compatibility.md#preflight-check) 的集群(原生 Kubernetes、kubeadm、k3s、kind 等)中,只需几条命令即可试用 KubeUser:

```bash
# 1. 安装 cert-manager(webhook TLS 所需)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.2/cert-manager.yaml
kubectl wait --for=condition=ready pod -l app=cert-manager -n cert-manager --timeout=60s

# 2. 安装 KubeUser(使用当前 kubeconfig 中的 API server 地址)
helm repo add kubeuser https://openkube-hub.github.io/KubeUser

export KUBERNETES_API_SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')

helm install kubeuser kubeuser/kubeuser \
  --namespace kubeuser --create-namespace \
  --set env.KUBERNETES_API_SERVER="$KUBERNETES_API_SERVER"

# 3. 创建一个 User
cat <<EOF | kubectl apply -f -
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: alice
spec:
  auth:
    type: x509
  clusterRoles:
    - existingClusterRole: view
EOF

# 4. 获取 kubeconfig 并使用
kubectl get secret alice-kubeconfig -n kubeuser \
  -o jsonpath='{.data.config}' | base64 -d > alice.kubeconfig
kubectl --kubeconfig alice.kubeconfig get pods -A
```

生产环境部署请参考下文的 [安装](#安装) 章节。

---

## 功能特性

#### ✅ 已实现

- [x] **声明式 User CRD** —— 支持状态跟踪、Conditions 与 Finalizer,确保资源生命周期干净可控
- [x] **自动证书签发** —— 与 Kubernetes CSR API 无缝集成
- [x] **有状态的轮换引擎** —— 基于 **Shadow Secret** 模式的可恢复多步轮换;控制器重启后可断点续跑
- [x] **原子化 Secret 更新** —— 零停机的凭据切换,失败时自动回滚
- [x] **动态 RBAC 协调** —— 自动管理 RoleBinding 与 ClusterRoleBinding
- [x] **Mutating 与 Validating Webhook** —— 通过 cert-manager CA 注入的 TLS 保护
- [x] **可配置的 CSR Signer** —— 可指向自定义 signer,只要其 CA 被 API server 信任用于客户端认证
- [x] **反雪崩设计** —— 带抖动的智能 requeue、24h TTL 下限、33% 续期窗口,以及幂等的单次状态更新 reconcile 路径
- [x] **高可用** —— 通过 Helm 提供 Leader 选举与多副本部署
- [x] **Prometheus 指标与告警** —— 轮换计数器、耗时直方图、到期 Gauge,预置 Grafana 仪表盘和 PrometheusRule 告警
- [x] **Kubernetes 事件** —— 通过 `kubectl describe user` 输出结构化事件
- [x] **状态 Conditions** —— 标准的 `Ready`、`Renewing`、`AutoRenewal` 条件,便于声明式状态检查
- [x] **kubectl 打印列** —— `kubectl get users` 展示 Phase、AutoRenew、Expiry、NextRenewal、Age、Message

#### 🚧 规划中

- [ ] **删除告警事件** —— User 删除时通过 admission warning 和 Warning 事件提醒:已签发证书在自然过期前仍然密码学有效(Kubernetes 不会为客户端证书查询 CRL/OCSP)
- [ ] **kubectl 插件** —— `kubectl kubeuser kubeconfig <name>`,替代手动 `kubectl get secret | base64 -d` 流程
- [ ] **审计日志** —— 每一次证书签发与轮换的不可变记录
- [ ] **短生命周期证书 (< 24h)** —— 面向零信任场景的临时访问
- [ ] **ServiceAccount Token 认证** —— 新增 `spec.auth.type: serviceAccountToken`,面向完全无法签发 client-auth CSR 的集群(如 EKS):Token 认证既不需要 signer,也不需要修改 API server 启动参数
- [ ] **可插拔的证书签发后端** —— 支持通过 cert-manager、Vault 或 AWS Private CA 签发证书,替代集群 CSR API,适用于自有 CA 已配置在 API server `--client-ca-file` 中的集群
- [ ] **ECDSA 密钥支持** —— 通过 `spec.auth.keyAlgorithm` 配置密钥算法
- [ ] **OpenTelemetry Tracing** —— 覆盖 reconcile 与轮换路径的端到端追踪
- [ ] **示例 Role 清单** —— 精选的、可直接应用的 `Role`/`ClusterRole` YAML 集合(只读、开发、命名空间管理员等常见访问模式)
- [ ] **自助 Kubeconfig 引导与同步** —— `kubeuser init`/`kubeuser sync` CLI,支持邮件下发的一次性引导 Token 和基于 mTLS 认证的凭据同步 ([跟踪 issue](https://github.com/openkube-hub/KubeUser/issues/111))

---

## 安全须知

**删除 User 不会使已签发的证书失效。**

删除 User 时:
- RBAC 绑定会立即被移除(访问权限被撤销)
- 相关 Secret 会被删除
- 证书在自然过期前仍然密码学有效

请据此规划 TTL。对短期访问场景,建议使用较短的 `ttl` 并设置 `autoRenew: false`。

---

## 安装

### 前置条件

- Kubernetes v1.28+
- 具有 cluster-admin 权限的 kubectl
- cert-manager(webhook 证书所需)

#### 安装 cert-manager

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.2/cert-manager.yaml
kubectl wait --for=condition=ready pod -l app=cert-manager -n cert-manager --timeout=60s
```

### 方式 1:Helm(推荐)

```bash
helm repo add kubeuser https://openkube-hub.github.io/KubeUser
helm repo update

export KUBERNETES_API_SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')

helm upgrade --install kubeuser kubeuser/kubeuser \
  --create-namespace \
  --namespace kubeuser \
  --version <version> \
  --set env.KUBERNETES_API_SERVER="$KUBERNETES_API_SERVER"

# 验证
kubectl get pods -n kubeuser
kubectl get certificates -n kubeuser
```

> 所有资源名称都会以 Helm release 名作为前缀。使用 `helm search repo kubeuser --versions` 查看可用版本。

### 方式 2:Kustomize

```bash
git clone https://github.com/openkube-hub/KubeUser.git
cd KubeUser
kubectl create namespace kubeuser
kubectl apply -k config/default
kubectl wait --for=condition=ready pod -l control-plane=controller-manager -n kubeuser --timeout=120s
```

### 方式 3:本地开发 (kind)

```bash
make docker-build
kind load docker-image ghcr.io/openkube-hub/kubeuser-controller:latest --name <cluster-name>
kubectl apply -k config/default
kubectl patch deployment kubeuser-controller-manager -n kubeuser \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"manager","imagePullPolicy":"Never"}]}}}}'
```

---

## 使用方式

### 默认值机制

KubeUser 通过 Mutating Webhook 在创建时把默认值持久化写入 User Spec:

```yaml
# 你提交:
spec:
  auth:
    type: x509

# Webhook 持久化后:
spec:
  auth:
    type: x509
    ttl: "2160h"      # 来自 KUBEUSER_DEFAULT_TTL
    autoRenew: true   # 来自 KUBEUSER_DEFAULT_AUTORENEW
```

查看已应用的默认值:`kubectl get user <name> -o yaml`

通过 Helm 自定义默认值:
```bash
helm upgrade --install kubeuser kubeuser/kubeuser \
  --set authDefaults.ttl=720h \
  --set authDefaults.autoRenew=false
```

> **重要:** `authDefaults` 的修改只对**升级之后**新建的 User 生效,已有 User 保留其原有的持久化默认值。

### 基础用户(命名空间级访问)

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: alice
spec:
  auth:
    type: x509        # 必填:目前仅支持 'x509'
    ttl: "72h"        # 可选:默认 2160h(90 天)
    autoRenew: false  # 可选:默认 true
  roles:
    - namespace: "development"
      existingRole: "developer"
    - namespace: "staging"
      existingRole: "viewer"
```

### 集群级权限用户

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: bob-admin
spec:
  auth:
    type: x509
    ttl: "2160h"
    autoRenew: true
  clusterRoles:
    - existingClusterRole: "cluster-admin"
```

### 混合权限

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: contractor-jane
spec:
  auth:
    type: x509
    ttl: "720h"        # 30 天
    autoRenew: true
    renewBefore: "72h" # 到期前 3 天续期(覆盖 33% 规则)
  roles:
    - namespace: "project-x"
      existingRole: "developer"
    - namespace: "monitoring"
      existingClusterRole: "view"  # 将 ClusterRole 绑定到某一命名空间
  clusterRoles:
    - existingClusterRole: "view"
```

### 获取用户的 Kubeconfig

```bash
kubectl get secret <username>-kubeconfig -n kubeuser \
  -o jsonpath='{.data.config}' | base64 -d > /tmp/kubeconfig

kubectl --kubeconfig /tmp/kubeconfig get pods -n dev
```

### 字段说明

| 字段 | 类型 | 是否必填 | 说明 |
|-------|------|----------|-------------|
| `spec.auth` | `AuthSpec` | **是** | 认证配置 |
| `spec.auth.type` | `string` | **是** | 认证方式 —— 目前仅支持 `x509` |
| `spec.auth.ttl` | `string` | 否 | 证书有效期(默认 `2160h`) |
| `spec.auth.autoRenew` | `boolean` | 否 | 是否启用自动续期(默认 `true`) |
| `spec.auth.renewBefore` | `string` | 否 | 到期前多久开始续期。不能超过 TTL 的 90% |
| `spec.roles` | `[]RoleSpec` | 否 | 命名空间级角色绑定 |
| `spec.roles[].namespace` | `string` | 是 | 目标命名空间 |
| `spec.roles[].existingRole` | `string` | 是(或 `existingClusterRole`) | 同命名空间下已存在的 Role |
| `spec.roles[].existingClusterRole` | `string` | 是(或 `existingRole`) | 绑定到该命名空间的 ClusterRole |
| `spec.clusterRoles` | `[]ClusterRoleSpec` | 否 | 集群级角色绑定 |
| `spec.clusterRoles[].existingClusterRole` | `string` | 是 | 已存在的 ClusterRole |

> 每个 `spec.roles[]` 条目中,`existingRole` 与 `existingClusterRole` 必须且只能设置其中一个。

---

## 集群兼容性

KubeUser 通过 Kubernetes CSR API 签发客户端证书,因此要求集群提供一个能签发 `client auth` 证书、且其 CA 被 API server 信任的 signer(默认为 `kubernetes.io/kube-apiserver-client`)。

| 平台 | 状态 |
|------|------|
| kubeadm(原生)、kind、minikube、Kubespray、RKE2 | ✅ 已验证 |
| k3s、k0s、Talos、MicroK8s | ✅ 预期可用 |
| 全手工搭建的控制平面 | ⚠️ 取决于 `kube-controller-manager` 与 `--client-ca-file` 的参数配置 |
| **Amazon EKS** | ❌ 不支持 —— EKS 的 signer 不支持客户端证书签发 |
| GKE、AKS 及其他托管控制平面 | ⚠️ 未验证 —— 请先执行预检脚本 |

在不兼容的集群上,CSR 只会停留在 `Approved` 而永远不会被签发(Issued),因此 `User` 会一直处于 `Pending`,`<username>-kubeconfig` Secret 也永远不会创建。部署前请使用
[预检脚本](docs/cluster-compatibility.md#preflight-check) 确认:它会提交一个 client-auth CSR,预期结果是 `Approved,Issued`,而不是卡在 `Approved`。

若集群使用自定义 signer(例如 cert-manager CA issuer 转发到自建 signer 控制器),需同时设置 signer 名称与对应的 RBAC approve 授权:

```bash
helm install kubeuser kubeuser/kubeuser \
  --set signerName="<your-signer-name>" \
  --set rbac.signerResourceNames[0]="<your-signer-name>"
```

完整的预检脚本、EKS 细节与替代方案,以及 KubeUser 的目标场景,请参阅 **[集群兼容性](docs/cluster-compatibility.md)**。

---

## 配置

### 证书有效期限制

| 限制项 | 值 | 说明 |
|-------|-------|-------|
| 最小 TTL | 24h | 由 Validating Webhook 强制,防止雪崩式续期 |
| 最大 TTL | 受集群签名有效期限制(Kubernetes 默认 `8760h` / 1 年) | 通过在 `kube-controller-manager` 上配置 `--cluster-signing-duration` 可延长 |
| 默认 TTL | 2160h(90 天) | 由 Mutating Webhook 应用;可通过 `authDefaults.ttl` 修改 |

### 环境变量

| 变量 | 默认值 | 说明 |
|----------|---------|-------------|
| `KUBERNETES_API_SERVER` | `https://127.0.0.1:6443` | 写入生成的 kubeconfig 中的 API server 地址 |
| `CLUSTER_DOMAIN` | `cluster.local` | 集群 DNS 域名 |
| `KUBEUSER_DEFAULT_TTL` | `2160h` | 默认证书 TTL |
| `KUBEUSER_DEFAULT_AUTORENEW` | `true` | 默认自动续期行为 |
| `KUBEUSER_SIGNER_NAME` | `kubernetes.io/kube-apiserver-client` | CSR signer 名称 |

---

## 示例

开箱即用的入门清单位于 [`examples/`](examples/):

- [`examples/rbac/`](examples/rbac/) —— 一组入门级 `ClusterRole`(viewer、developer、namespace-admin、readonly),用于补足 Kubernetes 自带的 `view`/`edit`/`admin`/`cluster-admin` 覆盖不到的场景。
- [`examples/users/`](examples/users/) —— 常见模式(最小权限、开发者、on-call、多命名空间)的示例 `User` CR。

```bash
kubectl apply -f examples/rbac/
kubectl apply -f examples/users/minimal-viewer.yaml
```

## 文档

- [集群兼容性](docs/cluster-compatibility.md)
- [证书管理](docs/certificate-management.md)
- [自动续期](docs/auto-renewal.md)
- [Webhook 校验](docs/webhook-validation.md)
- [指标参考](docs/metrics.md)
- [访问指标](docs/accessing-metrics.md)
- [发行版验证](docs/release-verification.md)
- [故障排查](docs/troubleshooting.md)

---

## 🤝 贡献

我们欢迎各种形式的贡献 —— Bug 反馈、新功能、文档与测试。

完整的贡献指南(前置条件、本地环境搭建、代码风格、提交规范、测试与 PR 检查清单)请参见 **[CONTRIBUTING.md](./CONTRIBUTING.md)**。

---

## 🏛️ 社区

| 文档 | 说明 |
|----------|-------------|
| [CONTRIBUTING.md](./CONTRIBUTING.md) | 如何参与贡献 |
| [GOVERNANCE.md](./GOVERNANCE.md) | 项目角色、决策与发布流程 |
| [MAINTAINERS.md](./MAINTAINERS.md) | 现任及荣休 Maintainer |
| [SECURITY.md](./SECURITY.md) | 安全漏洞报告方式 |
| [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) | 社区行为准则 |

---

如果 KubeUser 对你有帮助,欢迎在 GitHub 上点一个 ⭐!
