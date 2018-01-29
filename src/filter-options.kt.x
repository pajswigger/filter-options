package burp;


class BurpExtender : IBurpExtender, IProxyListener, IHttpListener {
    companion object {
        lateinit var cb: IBurpExtenderCallbacks
        val extension = ".options"
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        cb = callbacks
        cb.setExtensionName("Filter OPTIONS")
        cb.registerProxyListener(this)
        cb.registerHttpListener(this)
    }

    override fun processProxyMessage(isRequest: Boolean, interceptedProxyMessage: IInterceptedProxyMessage) {
        if(!isRequest) {
            return
        }

        val request = interceptedProxyMessage.messageInfo.request
        val requestInfo = cb.helpers.analyzeRequest(request)
        val headers = requestInfo.headers
        var firstLine = headers.get(0)!!

        if(!firstLine.startsWith("OPTIONS")) {
            return
        }

        val delim = firstLine.lastIndexOf(' ')
        headers.set(0, firstLine.substring(0, delim) + extension + firstLine.substring(delim))
        interceptedProxyMessage.messageInfo.request = cb.helpers.buildHttpMessage(headers, request.copyOfRange(requestInfo.bodyOffset, request.size))
    }

    override fun processHttpMessage(toolFlag: Int, isRequest: Boolean, messageInfo: IHttpRequestResponse) {
        if(!isRequest) {
            return
        }

        val request = messageInfo.request
        val requestInfo = cb.helpers.analyzeRequest(request)
        val headers = requestInfo.headers
        var firstLine = headers.get(0)!!

        if(!firstLine.startsWith("OPTIONS")) {
            return
        }

        val delim = firstLine.lastIndexOf(' ')
        if(firstLine.substring(delim - extension.length, delim) != extension) {
            return
        }

        headers.set(0, firstLine.substring(0, delim - extension.length) + firstLine.substring(delim))
        messageInfo.request = cb.helpers.buildHttpMessage(headers, request.copyOfRange(requestInfo.bodyOffset, request.size))
    }
}