@load base/protocols/http
@load base/frameworks/notice

module PHP2SHELLDefense;

export {
    redef enum Notice::Type += { Large_PHP_POST };
    const min_request_bytes: count = 300000 &redef;
}

# Low-confidence HTTP metadata heuristic only: NOT PHP2Shell attribution.
# The header can be client-controlled and transfers can be chunked.
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig || to_lower(name) != "content-length" )
        return;
    if ( ! c?$http || ! c$http?$method || ! c$http?$uri )
        return;
    if ( c$http$method != "POST" || /\\.php([?]|$)/ !in to_lower(c$http$uri) )
        return;
    if ( /^[0-9]+$/ !in value )
        return;
    local size = to_count(value);
    if ( size < min_request_bytes )
        return;
    NOTICE([$note=Large_PHP_POST,
            $conn=c,
            $msg=fmt("Large PHP POST (declared Content-Length %d); generic heuristic", size)]);
    }
