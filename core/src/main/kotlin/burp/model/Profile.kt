package burp.model

import burp.IRequestInfo
import burp.IScannerInsertionPoint
import kotlinx.serialization.Serializable

@Serializable
data class Profile(
    val name: String,
    val type: ProfileType,
    val enabled: Boolean,
    val detail: ProfileDetail,
    val variables: Map<String, String>? = null,
    val rules: List<ProfileRule>,
    val rulesCondition: ConditionType = ConditionType.Or,
)

@Serializable
data class ProfileDetail(
    val author: String,
    val severity: Severity,
    val confidence: Confidence,
    val description: String,
    val links: List<String>,
)

@Serializable
data class ProfileRule(
    val payload: Payload? = null,
    val headers: Map<String, String>? = null,
    val matchers: List<Matcher> = listOf(),
    val matchersCondition: ConditionType = ConditionType.Or,
)

@Serializable
data class Payload(
    val part: PayloadPart,
    val name: String = "*",
    val oob: Boolean = false,
    val action: PayloadAction = PayloadAction.Replace,
    val values: List<String>,
)

@Serializable
data class Matcher(
    val part: MatcherPart,
    val type: MatcherType = MatcherType.Word,
    val values: List<String>,
    val greedy: Boolean = false,
    val negative: Boolean = false,
    val caseSensitive: Boolean = false,
    val condition: ConditionType = ConditionType.Or,
)

enum class Severity {
    High,
    Medium,
    Low,
    Information;
}

enum class Confidence {
    Certain,
    Firm,
    Tentative;
}

enum class PayloadPart {
    Any,
    Url,
    Xml,
    Json,
    Form,
    Body,
    Path,
    PathFile,
    PathFolder,
    Cookie,
    Header,
    NameUrl,
    NameUrlRaw,
    NameForm,
    NameCookie;
}

enum class PayloadAction {
    Append, // 后置
    Prepend, // 前置
    Replace; // 替换
}

enum class MatcherPart(val isRequest: Boolean) {
    Url(true),
    Host(true),
    Port(true),
    Path(true),
    Query(true),
    Method(true),
    ContentType(true),
    Request(true),
    RequestBody(true),
    RequestHeader(true),

    Status(false),
    ResponseTime(false),
    ResponseType(false),
    Response(false),
    ResponseBody(false),
    ResponseHeader(false);
}

enum class ContentType {
    None,
    UrlEncoded,
    MultiPart,
    XML,
    JSON,
    AMF,
    Unknown;
}

enum class MatcherType {
    Dsl,
    Word,
    Regex;
}

enum class ConditionType {
    Or,
    And;
}

enum class ProfileType {
    Active,
    Passive;
}

fun <T> ConditionType.evaluate(array: Array<T>, greedy: Boolean = false, predicate: (T) -> Boolean) = when (this) {
    ConditionType.Or -> if (greedy) array.fold(false) { acc, obj -> predicate(obj) || acc } else array.any(predicate)
    ConditionType.And -> array.all(predicate)
}

fun <T> ConditionType.evaluate(list: List<T>, greedy: Boolean = false, predicate: (T) -> Boolean) = when (this) {
    ConditionType.Or -> if (greedy) list.fold(false) { acc, obj -> predicate(obj) || acc } else list.any(predicate)
    ConditionType.And -> list.all(predicate)
}

val PayloadPart.code
    get() = when (this) {
        PayloadPart.Any -> Byte.MIN_VALUE
        PayloadPart.Url -> IScannerInsertionPoint.INS_PARAM_URL
        PayloadPart.Xml -> IScannerInsertionPoint.INS_PARAM_XML
        PayloadPart.Json -> IScannerInsertionPoint.INS_PARAM_JSON
        PayloadPart.Form -> IScannerInsertionPoint.INS_PARAM_BODY
        PayloadPart.Body -> IScannerInsertionPoint.INS_ENTIRE_BODY
        PayloadPart.Path -> (Byte.MIN_VALUE + 2).toByte()
        PayloadPart.PathFile -> IScannerInsertionPoint.INS_URL_PATH_FILENAME
        PayloadPart.PathFolder -> IScannerInsertionPoint.INS_URL_PATH_FOLDER
        PayloadPart.Cookie -> IScannerInsertionPoint.INS_PARAM_COOKIE
        PayloadPart.Header -> IScannerInsertionPoint.INS_HEADER
        PayloadPart.NameUrl -> IScannerInsertionPoint.INS_PARAM_NAME_URL
        PayloadPart.NameUrlRaw -> (Byte.MIN_VALUE + 3).toByte()
        PayloadPart.NameForm -> IScannerInsertionPoint.INS_PARAM_NAME_BODY
        PayloadPart.NameCookie -> (Byte.MIN_VALUE + 1).toByte()
    }

val ContentType.code
    get() = when (this) {
        ContentType.None -> IRequestInfo.CONTENT_TYPE_NONE
        ContentType.UrlEncoded -> IRequestInfo.CONTENT_TYPE_URL_ENCODED
        ContentType.MultiPart -> IRequestInfo.CONTENT_TYPE_MULTIPART
        ContentType.XML -> IRequestInfo.CONTENT_TYPE_XML
        ContentType.JSON -> IRequestInfo.CONTENT_TYPE_JSON
        ContentType.AMF -> IRequestInfo.CONTENT_TYPE_AMF
        ContentType.Unknown -> IRequestInfo.CONTENT_TYPE_UNKNOWN
    }

/*
INS_PARAM_URL: 0
INS_PARAM_BODY: 1
INS_PARAM_COOKIE: 2
INS_PARAM_XML: 3
INS_PARAM_XML_ATTR: 4
INS_PARAM_MULTIPART_ATTR: 5
INS_PARAM_JSON: 6
INS_PARAM_AMF: 7
INS_HEADER: 32
INS_URL_PATH_FOLDER: 33
INS_PARAM_NAME_URL: 34
INS_PARAM_NAME_BODY: 35
INS_ENTIRE_BODY: 36
INS_URL_PATH_FILENAME: 37
INS_USER_PROVIDED: 64
INS_EXTENSION_PROVIDED: 65
INS_UNKNOWN: 127
*/
