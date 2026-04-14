# Rules

本文档定义首版规则模型、匹配语义和处理顺序。

## 规则结构

```json
{
  "id": 1001,
  "name": "http_rst",
  "enabled": true,
  "priority": 100,
  "match": {
    "vlans": [100, 200],
    "src_prefixes": ["10.0.0.0/8"],
    "dst_prefixes": ["192.168.1.0/24"],
    "src_ports": [12345, 23456],
    "dst_ports": [80, 8080],
    "features": ["TCP_SYN", "HTTP_METHOD", "HTTP_11"]
  },
  "response": {
    "action": "RST"
  }
}