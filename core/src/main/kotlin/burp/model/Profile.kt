package burp.model

import burp.IScannerInsertionPoint
import burp.PathInsertionPointProvider
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
    val matchers: List<Matcher>,
    val matchersCondition: ConditionType = ConditionType.Or,
)

@Serializable
data class Payload(
    val part: PayloadPart,
    val name: String = "*",
    val action: PayloadAction = PayloadAction.Replace,
    val values: List<String>,
)

@Serializable
data class Matcher(
    val part: MatcherPart,
    val type: MatcherType = MatcherType.Word,
    val values: List<String>,
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
    NameForm;
}

enum class PayloadAction {
    Append, // 后置
    Prepend, // 前置
    Replace; // 替换
}

enum class MatcherPart {
    Url,
    Method,
    Request,
    RequestBody,
    RequestHeader,

    Status,
    Response,
    ResponseTime,
    ResponseType,
    ResponseBody,
    ResponseHeader;
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

fun <T> ConditionType.evaluate(array: Array<T>, predicate: (T) -> Boolean) = when (this) {
    ConditionType.Or -> array.any(predicate)
    ConditionType.And -> array.all(predicate)
}

fun <T> ConditionType.evaluate(list: List<T>, predicate: (T) -> Boolean) = when (this) {
    ConditionType.Or -> list.any(predicate)
    ConditionType.And -> list.all(predicate)
}

val PayloadPart.insertionPointType
    get() = when (this) {
        PayloadPart.Any -> Byte.MIN_VALUE
        PayloadPart.Url -> IScannerInsertionPoint.INS_PARAM_URL
        PayloadPart.Xml -> IScannerInsertionPoint.INS_PARAM_XML
        PayloadPart.Json -> IScannerInsertionPoint.INS_PARAM_JSON
        PayloadPart.Form -> IScannerInsertionPoint.INS_PARAM_BODY
        PayloadPart.Body -> IScannerInsertionPoint.INS_ENTIRE_BODY
        PayloadPart.Path -> PathInsertionPointProvider.INSERTION_POINT_TYPE
        PayloadPart.PathFile -> IScannerInsertionPoint.INS_URL_PATH_FILENAME
        PayloadPart.PathFolder -> IScannerInsertionPoint.INS_URL_PATH_FOLDER
        PayloadPart.Cookie -> IScannerInsertionPoint.INS_PARAM_COOKIE
        PayloadPart.Header -> IScannerInsertionPoint.INS_HEADER
        PayloadPart.NameUrl -> IScannerInsertionPoint.INS_PARAM_NAME_URL
        PayloadPart.NameForm -> IScannerInsertionPoint.INS_PARAM_NAME_BODY
    }
