# Reference: https://www.metamorphosite.com/one-way-hash-encryption-sha1-data-software
# This only works on ASCII

list sha1_chunks;
list sha1_words;

func sha1(data) {  # Step 1: Pick a string
    # Step 0: Initialize some variables
    local h0 = "01100111010001010010001100000001";
    local h1 = "11101111110011011010101110001001";
    local h2 = "10011000101110101101110011111110";
    local h3 = "00010000001100100101010001110110";
    local h4 = "11000011110100101110000111110000";
    
    # Step 2: Break it into characters
    local message = "";
    local i = 1;
    repeat length $data {
        local char = $data[i];
        log "Step 2: char=" & char;

        # Step 3: Convert characters to ASCII codes
        local ascii_code = ord(char);
        log "Step 3: ascii_code=" & ascii_code;

        # Step 4: Convert numbers into binary
        local bin_ascii = zfill(base_conv10to(ascii_code, B2_DIGITS), 8);
        log "Step 4: bin_ascii=" & bin_ascii;

        assert_eq length bin_ascii, 8, "length bin_ascii != 8. Do not use sha1 with non-ASCII chars. ";

        # Step 5: Add '1' to the end
        message &= bin_ascii;

        i++;
    }

    log "Step 5: message=" & message;

    message &= 1;
    log "Step 5+1: message=" & message;

    # Step 6: Append '0's' to the end
    until length message % 512 == 448{
        message &= 0;
    }

    log "Step 6: message=" & message;

    # Step 6.1: Append original message length (as bits!)
    message &= zfill(base_conv10to(length $data * 8, B2_DIGITS), 64);
    log "Step 6.1: message=" & message;

    # Step 7: 'Chunk' the message
    delete sha1_chunks;
    local chunk = "";
    i = 1;
    repeat length message {
        chunk &= message[i];
        if i % 512 == 0 {
            add chunk to sha1_chunks;
            chunk = "";
        }
        i++;
    }
    log "Step 7: chunks=" & sha1_chunks;

    local chunk_i = 1;
    repeat length sha1_chunks {
        chunk = sha1_chunks[chunk_i];

        # Step 8: Break the 'Chunk' into 'Words'
        delete sha1_words;
        i = 1;
        local word = "";
        repeat 512 {
            word &= chunk[i];
            if length word == 32 {
                add word to sha1_words;
                word = "";
            }
            i++;
        }

        log "Step 8: words=" & sha1_words;
        # Step 9: 'Extend' into 80 words
        i = 16;
        until i == 80 {
            log "Step 9: i=" & i;
            # Step 9.1: XOR
            local w1 = sha1_words[i - 2];
            local w2 = sha1_words[i - 7];
            local w3 = sha1_words[i - 13];
            local w4 = sha1_words[i - 15];

            local new = bstr_xor(w1, w2);
            new = bstr_xor(new, w3);
            new = bstr_xor(new, w4);

            # Step 9.2: Left rotate
            new = bstr_lrot(new, 1);
            add new to sha1_words;
            
            log "Step 9.2: new=" & new;
            
            i++;
        }
        # Step 10: Initialize some variables
        local a = h0;
        local b = h1;
        local c = h2;
        local d = h3;
        local e = h4;
        # Step 11: The main loop
        i = 0;
        repeat length sha1_words {
            word = sha1_words[i + 1];

            log "Step 12: a=" & a;
            log "Step 12: b=" & b;
            log "Step 12: c=" & c;
            log "Step 12: d=" & d;
            log "Step 12: e=" & e;

            local match_case = i // 20;  # TODO: when switch case is implemented, use it instead of if else
            if match_case < 2 {
                if match_case == 0 {  # i in 0..=19
                    # function 1
                    local f = bstr_or(bstr_and(b, c), bstr_and(bstr_not(b), d));
                    local k = "01011010100000100111100110011001";
                } else {  # i in 20..=39
                    # function 2
                    local f = bstr_xor(bstr_xor(b, c), d);
                    local k = "01101110110110011110101110100001";
                }
            } else {
                if match_case == 2 {  # i in 40..=59
                    # function 3
                    local f = bstr_or(bstr_or(bstr_and(b, c), bstr_and(b, d)), bstr_and(c, d));
                    local k = "10001111000110111011110011011100";
                } else {  # i in 60..=79
                    # function 4
                    local f = bstr_xor(bstr_xor(b, c), d);
                    local k = "11001010011000101100000111010110";
                }
            }

            # Step 11.2: Put them together
            log "Step 12t: f=" & f;
            log "Step 12t: k=" & k;
            log "Step 12t: word=" & word;

            local temp1 = bstr_lrot(a, 5);
            log "Step 12t: temp=" & temp1;

            temp1 = bstr_add(bstr_add(bstr_add(bstr_add(
                temp1,
                e), f), k), word);
            log "Step 12t: temp=" & temp1;

            # Now we need to truncate the result so that the next operations will work smoothly.
            # We will remove as much of the beginning(left) until the number is 32 bits or 'digits' long.
            local temp = "";
            local temp_i = length temp1;
            # you could use _hashlib_sha1_truncate32 but this here is slightly more efficient
            repeat 32 {
                temp = temp1[temp_i] & temp;
                temp_i--;
            }

            # The only thing left to do at this point is 're-set' some variables then start the loop over.
            # We will be setting the following variables as such:
            e = d;
            d = c;
            c = bstr_lrot(b, 30);
            b = a;
            a = temp;

            i++;
        }
        # Step 12: The end
        h0 = _hashlib_sha1_truncate32(bstr_add(h0, a));
        h1 = _hashlib_sha1_truncate32(bstr_add(h1, b));
        h2 = _hashlib_sha1_truncate32(bstr_add(h2, c));
        h3 = _hashlib_sha1_truncate32(bstr_add(h3, d));
        h4 = _hashlib_sha1_truncate32(bstr_add(h4, e));
        
        log "Step 12: h0=" & h0;
        log "Step 12: h1=" & h1;
        log "Step 12: h2=" & h2;
        log "Step 12: h3=" & h3;
        log "Step 12: h4=" & h4;

        chunk_i++;
    }

    # Finally the variables are converted into base 16 (hex) and joined together.
    h0 = zfill(base_conv(h0, B2_DIGITS, B16_DIGITS), 8);
    h1 = zfill(base_conv(h1, B2_DIGITS, B16_DIGITS), 8);
    h2 = zfill(base_conv(h2, B2_DIGITS, B16_DIGITS), 8);
    h3 = zfill(base_conv(h3, B2_DIGITS, B16_DIGITS), 8);
    h4 = zfill(base_conv(h4, B2_DIGITS, B16_DIGITS), 8);

    log "Step 12f: h0=" & h0;
    log "Step 12f: h1=" & h1;
    log "Step 12f: h2=" & h2;
    log "Step 12f: h3=" & h3;
    log "Step 12f: h4=" & h4;

    return h0 & h1 & h2 & h3 & h4;
}

func _hashlib_sha1_truncate32(v) {
    local ret = "";
    local i = length $v;
    repeat 32 {
        ret = $v[i] & ret;
        i--;
    }
    return ret;
}
