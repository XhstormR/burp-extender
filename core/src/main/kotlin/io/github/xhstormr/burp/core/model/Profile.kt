package io.github.xhstormr.burp.core.model

import kotlinx.serialization.Serializable

@Serializable
data class Profile(
    val name: String,
    val type: ProfileType,
    val enabled: Boolean,
    val detail: ProfileDetail,
    val variables: Map<String, String>? = null,
    val rules: Array<ProfileRule>,
    val rulesCondition: ConditionType = ConditionType.And,
)

@Serializable
data class ProfileDetail(
    val author: String,
    val severity: Severity,
    val confidence: Confidence,
    val description: String,
    val links: Array<String>,
)

@Serializable
data class ProfileRule(
    // val method: String,
    // val path: String,
    // val expression: String,
    // val headers: Map<String, String>? = null,
    // val search: String? = null,
    val matchers: Array<Matcher>,
    val matchersCondition: ConditionType = ConditionType.And,
)

@Serializable
data class Matcher(
    val part: MatcherPart,
    val type: MatcherType = MatcherType.Word,
    val values: Array<String>,
    val condition: ConditionType = ConditionType.And,
    val negative: Boolean = false,
    val ignoreCase: Boolean = false,
)

enum class MatcherPart {
    Url,
    Method,
    RequestBody,
    RequestHeader,

    Status,
    ResponseTime,
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
