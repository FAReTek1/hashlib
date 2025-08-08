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
    log sha1("A Test");
}
