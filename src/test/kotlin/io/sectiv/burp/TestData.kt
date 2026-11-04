package io.sectiv.burp

import io.sectiv.burp.core.CapturedExchange

object TestData {
    fun exchange(
        id: String = "e1",
        method: String = "GET",
        url: String = "https://app.example.com/api/users/1",
        host: String = "app.example.com",
        path: String = "/api/users/1",
        status: Int = 200,
        request: String = "GET $path HTTP/1.1\r\nHost: $host\r\nCookie: session=user-a\r\n\r\n",
        response: String = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"email\":\"alice@example.com\",\"name\":\"Alice\"}",
        timestamp: Long = 1_700_000_000_000,
        hits: Int = 1
    ) = CapturedExchange(
        id = id,
        source = "Proxy history",
        method = method,
        url = url,
        host = host,
        port = 443,
        secure = true,
        path = path,
        status = status,
        mime = "application/json",
        requestRaw = request,
        responseRaw = response,
        timestamp = timestamp,
        hits = hits
    )
}
