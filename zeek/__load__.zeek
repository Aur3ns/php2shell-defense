@load base/protocols/http
@load base/frameworks/notice

module PHP2SHELLDefense;

export {
    redef enum Notice::Type += { Upload_Progress_Field };
}

# Minimal safe starting point: no body capture and no alerts emitted.
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig ) return;
    }
