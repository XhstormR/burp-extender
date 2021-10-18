package io.github.xhstormr.burp.core

import burp.IHttpRequestResponse
import io.github.xhstormr.burp.core.model.Profile

abstract class BaseScanner(
    val profile: Profile
) {

    fun scan(
        baseRequestResponse: IHttpRequestResponse,
    ) {
    }
}
