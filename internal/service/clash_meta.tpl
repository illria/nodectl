mixed-port: 7890
redir-port: 7891
tproxy-port: 1536
ipv6: true
mode: Rule
allow-lan: true
disable-keep-alive: true
geodata-mode: true
geo-auto-update: true
geo-update-interval: 24
geox-url:
  asn: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"
experimental:
  http-headers:
    request:
      - name: "User-Agent"
        value: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36"
      - name: "Accept-Language"
        value: "en-US,en;q=0.9"
unified-delay: true
tcp-concurrent: true
log-level: silent
find-process-mode: always
global-client-fingerprint: chrome

# -------------------- 订阅提供商 --------------------
proxy-providers:
  中转机场:
    type: http
    interval: {{.ProxiesInterval}}
    url: "{{.RelaySubURL}}"
    path: ./proxy_providers/clash-node.yaml
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300
  落地机场:
    type: http
    interval: {{.ProxiesInterval}}
    url: "{{.ExitSubURL}}"
    path: ./proxy_providers/exit.yaml
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300
    override:
      dialer-proxy: '💠 中转选择'
      skip-proxy: false

profile:
  store-selected: true
  store-fake-ip: true

# -------------------- 嗅探与网卡模块 --------------------
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
    TLS:
      ports: [443, 5228, 8443]
    QUIC:
      ports: [443, 8443]
  force-domain:
    - "+.v2ex.com"
  skip-domain:
    - "Mijia Cloud"

tun:
  enable: false
  device: Meta
  stack: mixed
  dns-hijack:
    - any:53
    - tcp://any:53
  udp-timeout: 300
  auto-route: true
  strict-route: true
  auto-redirect: false
  auto-detect-interface: true

dns:
  enable: true
  ipv6: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 172.20.0.1/16
  fake-ip-filter:
    - "RULE-SET:CN_域"
    - "RULE-SET:Private_域"
    - "RULE-SET:GoogleFCM_域"
    - "+.3gppnetwork.org"
    - "+.xtracloud.net"
  direct-nameserver:
    - https://doh.pub/dns-query#🇨🇳 大陆&h3=false
    - https://dns.alidns.com/dns-query#🇨🇳 大陆&h3=true
  proxy-server-nameserver:
    - https://doh.pub/dns-query#🇨🇳 大陆&h3=false
    - https://dns.alidns.com/dns-query#🇨🇳 大陆&h3=true
  nameserver-policy:
    "RULE-SET:{{.NameserverPolicyRuleSet}}":
       - https://doh.pub/dns-query#🇨🇳 大陆&h3=false
       - https://dns.alidns.com/dns-query#🇨🇳 大陆&h3=true
  nameserver:
    - https://dns.google/dns-query#DNS连接&h3=true
    - https://cloudflare-dns.com/dns-query#DNS连接&h3=true

proxies:
    - {name: 🇨🇳 大陆, type: direct, udp: true}
    - {name: ⛔️ 拒绝连接, type: reject}
    - {name: 🌐 DNS_Hijack, type: dns}

# -------------------- 策略组锚点定义 --------------------
# 个人地区策略：保留 NodeCTL 的中转/落地模型，同时复刻原配置的地区自动/手动选择逻辑。
proxy_groups: &proxy_groups
  type: select
  proxies:
    - 默认代理
    - 自动选择
    - 手动选择
    - 香港地区
    - 日本地区
    - 新加坡地区
    - 美国地区
    - 英国地区
    - 德国地区
    - 台湾地区
    - 韩国地区
    - 荷兰地区
    - 波兰地区
    - 摩尔多瓦地区
    - 芬兰地区
    - 印度地区
    - 泰国地区
    - 法国地区
    - 中国大陆地区
    - 🇨🇳 大陆
    - ⛔️ 拒绝连接

# -------------------- 策略组自动生成 --------------------
proxy-groups:
  - name: '💠 中转选择'
    type: select
    proxies:
      - 🇨🇳 大陆
    use:
      - 中转机场

  # 原配置“自动选择”仅筛选香港节点；保留原有行为。
  - name: 自动选择
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(香港|^HK|^🇭🇰)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 手动选择
    type: select
    proxies:
      - 🇨🇳 大陆
    use:
      - 落地机场

  - name: 香港自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(香港|^HK|^🇭🇰)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 香港地区
    type: select
    proxies:
      - 香港自动
    use:
      - 落地机场
    filter: "(?i)(香港|HK|Hong Kong)"

  - name: 日本自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(日本|^JP|^🇯🇵)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 日本地区
    type: select
    proxies:
      - 日本自动
    use:
      - 落地机场
    filter: "(?i)(日本|JP|Japan)"

  - name: 新加坡自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(新加坡|^SG|^🇸🇬)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 新加坡地区
    type: select
    proxies:
      - 新加坡自动
    use:
      - 落地机场
    filter: "(?i)(新加坡|SG|Singapore)"

  - name: 美国自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(美国|^🇺🇸)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 美国地区
    type: select
    proxies:
      - 美国自动
    use:
      - 落地机场
    filter: "(?i)(美国|US|USA|United States)"

  - name: 英国自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(英国|^🇬🇧)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 英国地区
    type: select
    proxies:
      - 英国自动
    use:
      - 落地机场
    filter: "(?i)(英国|UK|United Kingdom)"

  - name: 德国自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(德国|^🇩🇪)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 德国地区
    type: select
    proxies:
      - 德国自动
    use:
      - 落地机场
    filter: "(?i)(德国|DE|Germany)"

  - name: 台湾自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(台湾|^🇹🇼)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 台湾地区
    type: select
    proxies:
      - 台湾自动
    use:
      - 落地机场
    filter: "(?i)(台湾|TW|Taiwan)"

  - name: 韩国自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(韩国|^🇰🇷)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 韩国地区
    type: select
    proxies:
      - 韩国自动
    use:
      - 落地机场
    filter: "(?i)(韩国|KR|Korea)"

  - name: 荷兰自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(荷兰|^🇳🇱)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 荷兰地区
    type: select
    proxies:
      - 荷兰自动
    use:
      - 落地机场
    filter: "(?i)(荷兰|NL|Netherlands)"

  - name: 波兰自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(波兰|^🇵🇱)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 波兰地区
    type: select
    proxies:
      - 波兰自动
    use:
      - 落地机场
    filter: "(?i)(波兰|PL|Poland)"

  - name: 摩尔多瓦自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(摩尔多瓦|^🇲🇩)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 摩尔多瓦地区
    type: select
    proxies:
      - 摩尔多瓦自动
    use:
      - 落地机场
    filter: "(?i)(摩尔多瓦|Moldova)"

  - name: 芬兰自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(芬兰|^🇫🇮)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 芬兰地区
    type: select
    proxies:
      - 芬兰自动
    use:
      - 落地机场
    filter: "(?i)(芬兰|Finland)"

  - name: 印度自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(印度|^🇮🇳)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 印度地区
    type: select
    proxies:
      - 印度自动
    use:
      - 落地机场
    filter: "(?i)(印度|IN|India)"

  - name: 泰国自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(泰国|^🇹🇭)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 泰国地区
    type: select
    proxies:
      - 泰国自动
    use:
      - 落地机场
    filter: "(?i)(泰国|TH|Thailand)"

  - name: 法国自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(法国|KataBump|^🇫🇷)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 法国地区
    type: select
    proxies:
      - 法国自动
    use:
      - 落地机场
    filter: "(?i)(法国|FR|France|KataBump)"

  - name: 中国大陆自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(北京|乌兰察布|大陆)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 中国大陆地区
    type: select
    proxies:
      - 中国大陆自动
    use:
      - 落地机场
    filter: "(?i)(北京|乌兰察布|大陆)"

  - name: 默认代理
    type: select
    proxies:
      - 自动选择
      - 手动选择
      - 香港地区
      - 日本地区
      - 新加坡地区
      - 美国地区
      - 英国地区
      - 德国地区
      - 台湾地区
      - 韩国地区
      - 荷兰地区
      - 波兰地区
      - 摩尔多瓦地区
      - 芬兰地区
      - 印度地区
      - 泰国地区
      - 法国地区
      - 中国大陆地区

  - name: 总模式
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/All.svg"
    type: select
    proxies:
      - 默认代理
      - 自动选择
      - 手动选择
      - 香港地区
      - 日本地区
      - 新加坡地区
      - 美国地区
      - 英国地区
      - 德国地区
      - 台湾地区
      - 韩国地区
      - 荷兰地区
      - 波兰地区
      - 摩尔多瓦地区
      - 芬兰地区
      - 印度地区
      - 泰国地区
      - 法国地区
      - 中国大陆地区
      - 🇨🇳 大陆
      - ⛔️ 拒绝连接

  - name: GLOBAL
    type: select
    proxies:
      - 默认代理
      - 自动选择
      - 手动选择
      - 香港地区
      - 日本地区
      - 新加坡地区
      - 美国地区
      - 英国地区
      - 德国地区
      - 台湾地区
      - 韩国地区
      - 荷兰地区
      - 波兰地区
      - 摩尔多瓦地区
      - 芬兰地区
      - 印度地区
      - 泰国地区
      - 法国地区
      - 中国大陆地区
{{range .ActiveModules}}
  {{if ne .Type "reject"}}
      - {{.Name}}
  {{end}}
{{end}}
{{range .CustomProxies}}
      - {{.Name}}
{{end}}

  - name: 订阅更新
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Update.svg"
    type: select
    proxies:
      - 🇨🇳 大陆
      - 总模式

{{range .ActiveModules}}
  {{if ne .Type "reject"}}
  - name: {{.Name}}
    {{if .Icon}}icon: "{{.Icon}}"{{end}}
    <<: *proxy_groups
  {{end}}
{{end}}

  - name: DNS连接
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/DNS.svg"
    <<: *proxy_groups

  - name: 漏网之鱼
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/HBASE-copy.svg"
    <<: *proxy_groups

{{range .CustomProxies}}
  - name: {{.Name}}
    icon: "{{if .Icon}}{{.Icon}}{{else}}https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/User.svg{{end}}"
    <<: *proxy_groups
{{end}}

# -------------------- 规则集行为锚点 --------------------
rule-anchor:
  Local: &Local
    {type: file, behavior: classical, format: text}
  Classical: &Classical
    {type: http, behavior: classical, format: text, interval: {{.PublicRulesInterval}}}
  IPCIDR: &IPCIDR
    {type: http, behavior: ipcidr, format: mrs, interval: {{.PublicRulesInterval}}}
  Domain: &Domain
    {type: http, behavior: domain, format: mrs, interval: {{.PublicRulesInterval}}}

# -------------------- 规则集自动挂载 --------------------
rule-providers:
  我的直连规则:
    <<: *Classical
    interval: {{.RulesInterval}}
    url: "{{.BaseURL}}/sub/rules/direct?token={{.Token}}"
    path: ./rules/direct.list

{{range .CustomProxies}}
  {{.Name}}_自定义分流:
    <<: *Classical
    interval: {{$.RulesInterval}}
    url: "{{$.BaseURL}}/sub/rules/proxy/{{.ID}}?token={{$.Token}}"
    path: ./rules/{{.Name}}_Custom.list
{{end}}

  WebRTC_端/域:
    <<: *Classical
    path: ./rules/WebRTC.list
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/rules/WebRTC.list"

  CN_IP:
    <<: *IPCIDR
    path: ./rules/CN_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cn.mrs"
  CN_域:
    <<: *Domain
    path: ./rules/CN_域.mrs
    url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/cn.mrs"

  Private_域:
    <<: *Domain
    path: ./rules/LAN.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Lan/Lan_OCD_Domain.mrs"
  Private_IP:
    <<: *IPCIDR
    path: ./rules/Private_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Lan/Lan_OCD_IP.mrs"

{{range .ActiveModules}}
  {{if .DomainURL}}
  {{.Name}}_域:
    <<: *Domain
    path: ./rules/{{.Name}}_Domain.mrs
    url: "{{.DomainURL}}"
  {{end}}
  {{if .IPURL}}
  {{.Name}}_IP:
    <<: *IPCIDR
    path: ./rules/{{.Name}}_IP.mrs
    url: "{{.IPURL}}"
  {{end}}
  {{if .URL}}
  {{.Name}}_用户自定义:
    <<: *Classical
    interval: {{$.RulesInterval}}
    path: ./rules/{{.Name}}_User_Custom.yaml
    url: "{{.URL}}"
  {{end}}
{{end}}

# -------------------- 路由规则分发 --------------------
rules:
  # 与个人配置保持一致：优先阻断常见 STUN/WebRTC 端口与关键字。
  - DST-PORT,3478,⛔️ 拒绝连接
  - DST-PORT,5349,⛔️ 拒绝连接
  - DST-PORT,19302,⛔️ 拒绝连接
  - DST-PORT,19305,⛔️ 拒绝连接
  - DST-PORT,19307,⛔️ 拒绝连接
  - DST-PORT,19308,⛔️ 拒绝连接
  - DOMAIN-KEYWORD,stun,⛔️ 拒绝连接

  # 本地/私网保持直连。
  - IP-CIDR,127.0.0.0/8,🇨🇳 大陆,no-resolve
  - IP-CIDR,10.0.0.0/8,🇨🇳 大陆,no-resolve
  - IP-CIDR,172.16.0.0/12,🇨🇳 大陆,no-resolve
  - IP-CIDR,192.168.0.0/16,🇨🇳 大陆,no-resolve
  - DOMAIN-SUFFIX,local,🇨🇳 大陆

  - RULE-SET,我的直连规则,🇨🇳 大陆
  - RULE-SET,WebRTC_端/域,⛔️ 拒绝连接
{{range .ActiveModules}}
  {{if eq .Type "reject"}}
  {{$target := "⛔️ 拒绝连接"}}
  {{range .ExtraRules}}
  - {{.}},{{$target}}
  {{end}}
  {{if .DomainURL}}
  - RULE-SET,{{.Name}}_域,{{$target}}
  {{end}}
  {{if .IPURL}}
  - RULE-SET,{{.Name}}_IP,{{$target}}
  {{end}}
  {{if .URL}}
  - RULE-SET,{{.Name}}_用户自定义,{{$target}}
  {{end}}
  {{end}}
{{end}}
{{range .CustomProxies}}
  - RULE-SET,{{.Name}}_自定义分流,{{.Name}}
{{end}}
  - DST-PORT,53,🌐 DNS_Hijack
  - DST-PORT,853,DNS连接

{{range .ActiveModules}}
  {{if ne .Type "reject"}}
  {{$target := .Name}}
  {{range .ExtraRules}}
  - {{.}},{{$target}}
  {{end}}
  {{if .DomainURL}}
  - RULE-SET,{{.Name}}_域,{{$target}}
  {{end}}
  {{if .IPURL}}
  - RULE-SET,{{.Name}}_IP,{{$target}}
  {{end}}
  {{if .URL}}
  - RULE-SET,{{.Name}}_用户自定义,{{$target}}
  {{end}}
  {{end}}
{{end}}

  - DOMAIN,browserleaks.com,漏网之鱼
  - RULE-SET,CN_域,🇨🇳 大陆
  - RULE-SET,CN_IP,🇨🇳 大陆
  - RULE-SET,Private_域,🇨🇳 大陆
  - RULE-SET,Private_IP,🇨🇳 大陆
  - MATCH,默认代理