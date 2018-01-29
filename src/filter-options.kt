package burp;


class BurpExtender : IBurpExtender, IHttpListener {
    companion object {
        lateinit var cb: IBurpExtenderCallbacks
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        cb = callbacks
        cb.setExtensionName("Filter OPTIONS")
        cb.registerHttpListener(this)
    }

    override fun processHttpMessage(toolFlag: Int, isRequest: Boolean, messageInfo: IHttpRequestResponse) {
        if(isRequest) {
            return
        }

        val requestInfo = cb.helpers.analyzeRequest(messageInfo.request)
        if(!requestInfo.headers.get(0)!!.startsWith("OPTIONS")) {
            return
        }

        val response = messageInfo.response
        val responseInfo = cb.helpers.analyzeResponse(response)
        val headers = responseInfo.headers
        headers.add("Content-Type: application/octet-stream")
        messageInfo.response = cb.helpers.buildHttpMessage(headers, response.copyOfRange(responseInfo.bodyOffset, response.size))
    }
}
