@load base/protocols/http
@load base/frameworks/notice

module PHP2SHELLDefense;

export {
    redef enum Notice::Type += { Large_PHP_POST };
    const min_request_bytes: count = 300000 &redef;
}

global candidate: table[string] of bool &default=F;

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    candidate[c$uid] = method == "POST" &&
        /\.php([?]|$)/ in to_lower(original_URI);
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig || to_lower(name) != "content-length" ||
         ! candidate[c$uid] )
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

event connection_state_remove(c: connection)
    {
    delete candidate[c$uid];
    }
