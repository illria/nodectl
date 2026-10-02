proxy-providers:
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
      udp: true
  中转链:
    type: http
    interval: {{.ProxiesInterval}}
    url: "{{.ChainSubURL}}"
    path: ./proxy_providers/chains.yaml
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300
    override:
      udp: true

proxies:
    - {name: 🇨🇳 大陆, type: direct, udp: true}
    - {name: ⛔️ 拒绝连接, type: reject}

# -------------------- 软件策略通用选项 --------------------
# 软件模块可以选择总模式、手动/地区策略或直连/拒绝，不引用自身或 GLOBAL。
{{define "softwareOptions"}}
    type: select
    proxies:
      - 总模式
      - 直连落地
      - 中转线路
      - 手动选择
      - 香港地区
      - 香港自动
      - 日本地区
      - 日本自动
      - 新加坡地区
      - 新加坡自动
      - 美国地区
      - 美国自动
      - 英国地区
      - 英国自动
      - 德国地区
      - 德国自动
      - 台湾地区
      - 台湾自动
      - 韩国地区
      - 韩国自动
      - 荷兰地区
      - 荷兰自动
      - 波兰地区
      - 波兰自动
      - 摩尔多瓦地区
      - 摩尔多瓦自动
      - 芬兰地区
      - 芬兰自动
      - 印度地区
      - 印度自动
      - 泰国地区
      - 泰国自动
      - 法国地区
      - 法国自动
      - 中国大陆地区
      - 中国大陆自动
      - 🇨🇳 大陆
      - ⛔️ 拒绝连接
{{end}}

# -------------------- 策略组自动生成 --------------------
# 客户端只选择完整线路；地区组继续使用直连落地 Provider。
proxy-groups:
  - name: 总模式
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/All.svg"
    type: select
    proxies:
      - 手动选择
      - 直连落地
      - 中转线路
      - 香港地区
      - 香港自动
      - 日本地区
      - 日本自动
      - 新加坡地区
      - 新加坡自动
      - 美国地区
      - 美国自动
      - 英国地区
      - 英国自动
      - 德国地区
      - 德国自动
      - 台湾地区
      - 台湾自动
      - 韩国地区
      - 韩国自动
      - 荷兰地区
      - 荷兰自动
      - 波兰地区
      - 波兰自动
      - 摩尔多瓦地区
      - 摩尔多瓦自动
      - 芬兰地区
      - 芬兰自动
      - 印度地区
      - 印度自动
      - 泰国地区
      - 泰国自动
      - 法国地区
      - 法国自动
      - 中国大陆地区
      - 中国大陆自动
      - 🇨🇳 大陆
      - ⛔️ 拒绝连接
  - name: 直连落地
    type: select
    use:
      - 落地机场

  - name: 中转线路
    type: select
    use:
      - 中转链

  - name: 手动选择
    type: select
    use:
      - 落地机场
      - 中转链

{{range .ActiveModules}}
  {{if ne .Type "reject"}}
  - name: {{.Name}}
    {{if eq .Name "加密货币"}}icon: "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/bitcoin.svg"{{else if .Icon}}icon: "{{.Icon}}"{{end}}
{{template "softwareOptions"}}
  {{end}}
{{end}}

  - name: 香港地区
    type: select
    proxies:
      - 香港自动
    use:
      - 落地机场
    filter: "(?i)(香港|HK|Hong Kong)"

  - name: 香港自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(香港|^HK|^🇭🇰)"
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

  - name: 日本自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(日本|^JP|^🇯🇵)"
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

  - name: 新加坡自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(新加坡|^SG|^🇸🇬)"
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

  - name: 美国自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(美国|^🇺🇸)"
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

  - name: 英国自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(英国|^🇬🇧)"
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

  - name: 德国自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(德国|^🇩🇪)"
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

  - name: 台湾自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(台湾|^🇹🇼)"
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

  - name: 韩国自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(韩国|^🇰🇷)"
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

  - name: 荷兰自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(荷兰|^🇳🇱)"
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

  - name: 波兰自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(波兰|^🇵🇱)"
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

  - name: 摩尔多瓦自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(摩尔多瓦|^🇲🇩)"
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

  - name: 芬兰自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(芬兰|^🇫🇮)"
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

  - name: 印度自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(印度|^🇮🇳)"
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

  - name: 泰国自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(泰国|^🇹🇭)"
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

  - name: 法国自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(法国|KataBump|^🇫🇷)"
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

  - name: 中国大陆自动
    type: url-test
    use:
      - 落地机场
    filter: "(?i)(北京|乌兰察布|大陆)"
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: GLOBAL
    type: select
    proxies:
      - 总模式
      - 直连落地
      - 中转线路
{{range .ActiveModules}}
  {{if ne .Type "reject"}}
      - {{.Name}}
  {{end}}
{{end}}
      - 手动选择
      - 香港地区
      - 香港自动
      - 日本地区
      - 日本自动
      - 新加坡地区
      - 新加坡自动
      - 美国地区
      - 美国自动
      - 英国地区
      - 英国自动
      - 德国地区
      - 德国自动
      - 台湾地区
      - 台湾自动
      - 韩国地区
      - 韩国自动
      - 荷兰地区
      - 荷兰自动
      - 波兰地区
      - 波兰自动
      - 摩尔多瓦地区
      - 摩尔多瓦自动
      - 芬兰地区
      - 芬兰自动
      - 印度地区
      - 印度自动
      - 泰国地区
      - 泰国自动
      - 法国地区
      - 法国自动
      - 中国大陆地区
      - 中国大陆自动
      - 🇨🇳 大陆
      - ⛔️ 拒绝连接
{{range .CustomProxies}}
      - {{.Name}}
{{end}}

  - name: 订阅更新
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Update.svg"
    type: select
    proxies:
      - 🇨🇳 大陆
      - 总模式

{{range .CustomProxies}}
  - name: {{.Name}}
    icon: "{{if .Icon}}{{.Icon}}{{else}}https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/User.svg{{end}}"
{{template "softwareOptions"}}
{{end}}

# -------------------- 规则集自动挂载 --------------------
rule-providers:
  我的直连规则:
    type: http
    behavior: classical
    format: text
    interval: {{.RulesInterval}}
    url: "{{.BaseURL}}/sub/rules/direct?token={{.Token}}"
    path: ./rules/direct.list

{{range .CustomProxies}}
  {{.Name}}_自定义分流:
    type: http
    behavior: classical
    format: text
    interval: {{$.RulesInterval}}
    url: "{{$.BaseURL}}/sub/rules/proxy/{{.ID}}?token={{$.Token}}"
    path: ./rules/{{.Name}}_Custom.list
{{end}}

  WebRTC_端/域:
    type: http
    behavior: classical
    format: text
    interval: {{$.PublicRulesInterval}}
    path: ./rules/WebRTC.list
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/rules/WebRTC.list"

{{range .ActiveModules}}
  {{if .DomainURL}}
  {{.Name}}_域:
    type: http
    behavior: domain
    format: mrs
    interval: {{$.PublicRulesInterval}}
    path: ./rules/{{.Name}}_Domain.mrs
    url: "{{.DomainURL}}"
  {{end}}
  {{if .IPURL}}
  {{.Name}}_IP:
    type: http
    behavior: ipcidr
    format: mrs
    interval: {{$.PublicRulesInterval}}
    path: ./rules/{{.Name}}_IP.mrs
    url: "{{.IPURL}}"
  {{end}}
  {{if .URL}}
  {{.Name}}_用户自定义:
    type: http
    behavior: classical
    format: text
    interval: {{$.RulesInterval}}
    path: ./rules/{{.Name}}_User_Custom.yaml
    url: "{{.URL}}"
  {{end}}
{{end}}

# -------------------- 路由规则分发 --------------------
rules:
  # 与个人配置保持一致：优先阻断常见 STUN/WebRTC 端口与关键字。
  - DST-PORT,3478,REJECT
  - DST-PORT,5349,REJECT
  - DST-PORT,19302,REJECT
  - DST-PORT,19305,REJECT
  - DST-PORT,19307,REJECT
  - DST-PORT,19308,REJECT
  - DOMAIN-KEYWORD,stun,REJECT

  # 本地/私网保持直连。
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - DOMAIN-SUFFIX,local,DIRECT

  - RULE-SET,我的直连规则,DIRECT,no-resolve
  - RULE-SET,WebRTC_端/域,REJECT,no-resolve

{{range .ActiveModules}}
  {{if eq .Type "reject"}}
  {{$target := "REJECT"}}
  {{range .ExtraRules}}
  - {{.}},{{$target}}
  {{end}}
  {{if .DomainURL}}
  - RULE-SET,{{.Name}}_域,{{$target}}
  {{end}}
  {{if .IPURL}}
  - RULE-SET,{{.Name}}_IP,{{$target}},no-resolve
  {{end}}
  {{if .URL}}
  - RULE-SET,{{.Name}}_用户自定义,{{$target}},no-resolve
  {{end}}
  {{end}}
{{end}}
{{range .CustomProxies}}
  - RULE-SET,{{.Name}}_自定义分流,{{.Name}},no-resolve
{{end}}

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
  - RULE-SET,{{.Name}}_IP,{{$target}},no-resolve
  {{end}}
  {{if .URL}}
  - RULE-SET,{{.Name}}_用户自定义,{{$target}},no-resolve
  {{end}}
  {{end}}
{{end}}

  - GEOSITE,CN,DIRECT
  - GEOIP,CN,DIRECT,no-resolve
  - MATCH,总模式
