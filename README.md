# 旁路分析与主动响应服务

一个面向镜像流量场景的前置裁决与响应编排服务。

## 定位

作为旁路流量入口侧的前置裁决层，负责在后端分析之前完成识别、分类、分流、事件提取和主动响应触发。  
低延迟 TCP reset 由 XDP 同步 TX 直接响应；其他 spoof 响应经 XSK 交给用户态执行。

## 特性

- 入口侧前置裁决
- 轻量规则驱动
- 流量分类与分流
- 统一事件输出
- TCP reset 同步 TX response
- ICMP/ARP/TCP handshake XSK redirect path for user-space response execution
- 基础状态可视化

## 架构

```mermaid
flowchart BT
    A[镜像流量]
    B[独立流量镜像网卡]

    subgraph Service[旁路分析与主动响应服务]
        C[数据面模块]
        D[观测事件]
        K[XSK TX 响应通道]
        E[深度分析接入模块]
        G[响应执行模块]
        I[控制面模块]
        J[管理与展示模块]
    end

    F[后端分析系统]
    H[主动响应]

    A --> B --> C
    C --> D
    C --> K --> G
    D --> E --> F
    C -.TCP reset XDP_TX.-> H
    G --> H

    I -.规则 / 配置 / 策略下发.-> C
    I -.规则快照 / 响应配置.-> G
    I -.分析接入配置.-> E
    J <--> I
```

## 环境

- OS
  - Ubuntu 22.04+
  - Debian 11+
  - RHEL 9+
- NIC
  - 独立流量镜像网卡
