
func _hashlib_truncate32(v) {
    local ret = "";
    local i = length $v;
    repeat 32 {
        ret = $v[i] & ret;
        i--;
    }
    return ret;
}

%include inflator/hashlib/src/sha1
%include inflator/hashlib/src/sha2
