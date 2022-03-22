# burp-extender

## Single-extension scan

1. When creating a new scan, click `Select from library` on the `Scan configuration` tab
2. Pick `Audit checks - extensions only` which is built into Burp Suite Pro 2.x
3. Disable every other extension (if applicable) that have an active scan check registered (such as ActiveScan++, Backslash powered scanning, Burp Bounty, etc.)

## Reference

* https://httpbin.org
* https://petstore.swagger.io
* https://portswigger.net/burp/extender/api/allclasses-noframe.html
* https://github.com/lightbend/config/blob/main/HOCON.md
    * https://docs.tibco.com/pub/str/latest/doc/html/hocon/hocon-syntax-reference.html
* https://github.com/spring-projects/spring-framework/blob/main/src/docs/asciidoc/core/core-expressions.adoc
