# burp-extender

- [Configuration File Format](#configuration-file-format)
    * [Profile](#profile)
    * [ProfileDetail](#profiledetail)
    * [ProfileRule](#profilerule)
    * [Payload](#payload)
    * [Matcher](#matcher)
    * [Map](#map)
    * [ProfileType](#profiletype)
    * [Severity](#severity)
    * [Confidence](#confidence)
    * [ContentType](#contenttype)
    * [ConditionType](#conditiontype)
    * [PayloadAction](#payloadaction)
    * [PayloadPart](#payloadpart)
    * [MatcherPart](#matcherpart)
    * [MatcherType](#matchertype)
- [Single-extension scan](#single-extension-scan)
- [Reference](#reference)

一款 Burp Suite 插件，使用外部的配置文件来定义扫描器规则，扫描规则主要分为两类：主动扫描和被动扫描。 详细使用示例可以参考 `./assets/profiles/` 文件夹。

## Configuration File Format

配置文件使用 HOCON 格式描述，是 JSON 格式的超集。

### Profile

```yaml
name = poc-active-example
type = Active
enabled = true
detail = {}
variables = {}
rulesCondition = Or
rules = []
```

* `name`: string
    * 配置名称
* `type`: [ProfileType](#profiletype)
    * 配置类型
* `enabled`: true | false
    * 配置启用
* `detail`: [ProfileDetail](#profiledetail)
    * 配置描述
* `variables`: [Map](#map)
    * 规则变量，可以在匹配规则和荷载数据中使用，可选
* `rulesCondition`: [ConditionType](#conditiontype)
    * 规则条件，可以是 Or 或 And，默认值 `Or`
* `rules`: [[ProfileRule](#profilerule)]
    * 规则定义

### ProfileDetail

配置描述

```yaml
{
    severity = High
    confidence = Certain
    author = XhstormR
    description = "a brief description"
    links = [
        "https://example.com"
    ]
}
```

* `severity`: [Severity](#severity)
    * 问题严重性
* `confidence`: [Confidence](#confidence)
    * 问题可靠性
* `author`: string
    * 配置作者
* `description`: string
    * 问题详情
* `links`: [string]
    * 相关链接

### ProfileRule

规则定义

```yaml
{
    headers = {}
    payload = {}
    matchers = []
    matchersCondition = Or
}
```

* `headers`: [Map](#map)
    * 自定义请求头（主动扫描时使用），可选
* `payload`: [Payload](#payload)
    * 自定义荷载（主动扫描时使用），可选
* `matchersCondition`: [ConditionType](#conditiontype)
    * 规则条件，可以是 Or 或 And，默认值 `Or`
* `matchers`: [[Matcher](#matcher)]
    * 匹配规则

### Payload

自定义荷载（主动扫描时使用）

```yaml
{
    part = PathFile
    action = Replace
    name = "*"
    oob = false
    values = [
        """..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"""
    ]
}
```

* `part`: [PayloadPart](#payloadpart)
    * 荷载插入点
* `name`: string
    * 插入点名称，默认值 `*`，为 `*` 时表示匹配所有插入点名称，支持正则表达式
* `oob`: true | false
    * 是否使用带外流量来检测问题，默认值 `false`。启用后，荷载数据可以通过如下方式使用 `"ping -c1 #{OOB}"`
* `action`: [PayloadAction](#payloadaction)
    * 插入点行为，默认值 `Replace`
* `values`: [string]
    * 荷载数据

### Matcher

匹配规则

对于主动扫描，首先会检查请求类匹配点，满足条件后才会发送请求，之后再检查响应类匹配点。

```yaml
{
    part = RequestHeader
    type = Word
    condition = Or
    negative = false
    caseSensitive = false
    values = [
        "User-Agent"
    ]
}
```

* `part`: [MatcherPart](#matcherpart)
    * 匹配点
* `type`: [MatcherType](#matchertype)
    * 匹配值类型，默认值 `Word`
* `values`: [string]
    * 匹配值
* `negative`: true | false
    * 是否取反匹配结果，默认值 `false`
* `caseSensitive`: true | false
    * 是否大小写敏感，默认值 `false`
* `condition`: [ConditionType](#conditiontype)
    * 规则条件，可以是 Or 或 And，默认值 `Or`

### Map

字典数据，可以使用 SpEL 表达式。

```yaml
{
    key1 = "Hello"
    key2 = "#{randomInt(20, 30)}"
    key3 = "#{randomString(key2)}"
    key4 = "#{randomDouble(0.0,1.0) + 2}"
}
```

### ProfileType

配置类型

* `Active`: 主动扫描
* `Passive`: 被动扫描

### Severity

问题严重性

* `High`: 高
* `Medium`: 中
* `Low`: 低
* `Information`: 仅供参考

### Confidence

问题可靠性

* `Certain`: 肯定
* `Firm`: 暂定，可能是误报
* `Tentative`: 暂定，但很可能是误报

### ContentType

内容类型

* `None`: 无请求体
* `UrlEncoded`: url-encoded 格式
* `MultiPart`: multi-part 格式
* `XML`: XML 格式
* `JSON`: JSON 格式
* `AMF`: AMF 格式

### ConditionType

逻辑运算符

* `Or`: `||`，一真为真
* `And`: `&&`，全真为真

### PayloadAction

插入点行为

* `Append`: 后置，eg.`name=9527` -> `name=9527;sleep(12)--`
* `Prepend`: 前置，eg.`name=9527` -> `name=;sleep(12)--9527`
* `Replace`: 替换，eg.`name=9527` -> `name=;sleep(12)--`

### PayloadPart

插入点

请求:

```
POST /v2/pet?debug=true&proxy=true HTTP/2
Host: petstore.swagger.io
Cookie: RK=LVg8IU4rbe; ariaDefaultTheme=undefined; iip=0
Content-Length: 215
Sec-Ch-Ua: "(Not(A:Brand";v="8", "Chromium";v="99", "Google Chrome";v="99"
Accept: application/json
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36
Sec-Ch-Ua-Platform: "macOS"
Origin: https://petstore.swagger.io
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://petstore.swagger.io/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9

{
  "id": 0,
  "category": {
    "id": 0,
    "name": "string"
  },
  "name": "doggie",
  "photoUrls": [
    "string"
  ],
  "tags": [
    {
      "id": 0,
      "name": "string"
    }
  ],
  "status": "available"
}
```

* `Any`: 任意插入点
* `Url`: a
* `Xml`: a
* `Json`: a
* `Form`: a
* `Body`: a
* `PathFile`: a
* `PathFolder`: a
* `Cookie`: a
* `Header`: a
* `NameUrl`: a
* `NameForm`: a
* `NameCookie`: a

### MatcherPart

匹配点

请求:

```
POST /v2/pet?debug=true&proxy=true HTTP/2
Host: petstore.swagger.io
Cookie: RK=LVg8IU4rbe; ariaDefaultTheme=undefined; iip=0
Content-Length: 215
Sec-Ch-Ua: "(Not(A:Brand";v="8", "Chromium";v="99", "Google Chrome";v="99"
Accept: application/json
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36
Sec-Ch-Ua-Platform: "macOS"
Origin: https://petstore.swagger.io
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://petstore.swagger.io/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9

{
  "id": 0,
  "category": {
    "id": 0,
    "name": "string"
  },
  "name": "doggie",
  "photoUrls": [
    "string"
  ],
  "tags": [
    {
      "id": 0,
      "name": "string"
    }
  ],
  "status": "available"
}
```

响应:

```
HTTP/2 200 OK
Date: Fri, 01 Apr 2022 03:55:56 GMT
Content-Type: application/json
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, DELETE, PUT
Access-Control-Allow-Headers: Content-Type, api_key, Authorization
Server: Jetty(9.2.9.v20150224)

{"id":9222968140497182694,"category":{"id":0,"name":"string"},"name":"doggie","photoUrls":["string"],"tags":[{"id":0,"name":"string"}],"status":"available"}
```

* 请求
    * `Url`: 请求地址，eg.`https://petstore.swagger.io:443/v2/pet?debug=true&proxy=true`
    * `Host`: 请求主机，eg.`petstore.swagger.io`
    * `Path`: 请求路径，eg.`/v2/pet`
    * `Query`: 请求参数，eg.`debug=true&proxy=true`
    * `Method`: 请求方法，eg.`POST`
    * [`ContentType`](#contenttype): 内容类型，eg.`JSON`
    * `Request`: 整个请求，匹配结果支持高亮
    * `RequestBody`: 请求体，匹配结果支持高亮
    * `RequestHeader`: 请求头，匹配结果支持高亮
* 响应
    * `Status`: 响应状态，eg.`200`
    * `ResponseTime`: 响应时间，eg.`4000-5000` 代表匹配响应时间在 4s-5s 的请求
    * `ResponseType`: 响应类型，eg.`JSON`
    * `Response`: 整个响应，匹配结果支持高亮
    * `ResponseBody`: 响应体，匹配结果支持高亮
    * `ResponseHeader`: 响应头，匹配结果支持高亮

### MatcherType

匹配值类型

* `Word`: 纯文本
* `Regex`: 正则表达式
* `Dsl`: SpEL 表达式（TODO）

## Single-extension scan

1. When creating a new scan, click `Select from library` on the `Scan configuration` tab, and pick `Audit checks - extensions only`.
2. Disable every other extension (if applicable) that have an active scan check registered (such as ActiveScan++, Backslash powered scanning, Burp Bounty, etc.).

## Reference

* https://httpbin.org
* https://petstore.swagger.io
* https://portswigger.net/burp/extender/api/allclasses-noframe.html
* https://github.com/lightbend/config/blob/main/HOCON.md
    * https://docs.tibco.com/pub/str/latest/doc/html/hocon/hocon-syntax-reference.html
* https://github.com/spring-projects/spring-framework/blob/main/src/docs/asciidoc/core/core-expressions.adoc
* http://testphp.vulnweb.com
