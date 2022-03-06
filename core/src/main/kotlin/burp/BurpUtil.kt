package burp

fun IHttpRequestResponse.requestBody(bodyOffset: Int) = request.sliceArray(bodyOffset..request.lastIndex)
fun IHttpRequestResponse.responseBody(bodyOffset: Int) = response.sliceArray(bodyOffset..response.lastIndex)

fun IHttpRequestResponse.requestBodyString(bodyOffset: Int) = request.decodeToString(bodyOffset)
fun IHttpRequestResponse.responseBodyString(bodyOffset: Int) = response.decodeToString(bodyOffset)

fun IHttpRequestResponse.requestHeader(bodyOffset: Int) = request.sliceArray(0..bodyOffset)
fun IHttpRequestResponse.responseHeader(bodyOffset: Int) = response.sliceArray(0..bodyOffset)

fun IHttpRequestResponse.requestHeaderString(bodyOffset: Int) = request.decodeToString(0, bodyOffset)
fun IHttpRequestResponse.responseHeaderString(bodyOffset: Int) = response.decodeToString(0, bodyOffset)

fun HttpRequestResponseWrapper.toMarkedRequestResponse(burpExtender: IBurpExtenderCallbacks): IHttpRequestResponseWithMarkers =
    burpExtender.applyMarkers(
        this,
        requestInfoWrapper.markers.merge(),
        responseInfoWrapper.markers.merge(),
    )
