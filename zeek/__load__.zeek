@load base/protocols/http
@load base/frameworks/notice

module PHP2SHELLDefense;

export {
    redef enum Notice::Type += { Upload_Progress_Field };
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig ) return;
    if ( to_lower(name) == "content-type" &&
         /multipart\/form-data/ in to_lower(value) )
        c$http?$method;
    }
