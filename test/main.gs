costumes "blank.svg";

%include inflator/assert
%include inflator/char
%include inflator/base
%include inflator/string
%include inflator/math

%include inflator/hashlib

onflag {main;}
proc main {
    log sha1("A Test");
}
