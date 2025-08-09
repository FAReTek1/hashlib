costumes "blank.svg";

%include inflator/assert
%include inflator/char
%include inflator/math
%include inflator/string

%include inflator/base
%include inflator/bstr

%include inflator/hashlib

onflag {main;}
proc main {
    chunk1 = "A Test";
    chunk2 = "00011001010111001001100101   w1 00100111011100110010000001101000   w2 0110111101110111";
    assert_eq sha1(chunk1), "8F0C0855915633E4A7DE19468B3874C8901DF043", "sha1: ";
    assert_eq sha1(chunk2), "eb5e36b05aa4e94c9162d4aaf50a65014df7c92b", "sha1 2chunk: ";
    assert_eq sha256(chunk1), "3445f19bb7bb8de4bdad54ec2871b1ca5a761de0115f6f741e298e4cc8f633ee", "sha256: ";
    assert_eq sha256(chunk2), "261346981802bcc516ecde9425a72b4d1b5b1f9d0dd5e50d401b9c9e813b3335", "sha256 2chunk: ";
}
