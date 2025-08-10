# ref: https://www.nic.ad.jp/ja/tech/ipa/RFC3874EN.html
# This only works on ASCII

list sha224_chunks;
list sha224_words;
# 2. Initialize array of K constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311
list sha224_k = [
    "01000010100010100010111110011000",
    "01110001001101110100010010010001",
    "10110101110000001111101111001111",
    "11101001101101011101101110100101",
    "00111001010101101100001001011011",
    "01011001111100010001000111110001",
    "10010010001111111000001010100100",
    "10101011000111000101111011010101",
    "11011000000001111010101010011000",
    "00010010100000110101101100000001",
    "00100100001100011000010110111110",
    "01010101000011000111110111000011",
    "01110010101111100101110101110100",
    "10000000110111101011000111111110",
    "10011011110111000000011010100111",
    "11000001100110111111000101110100",
    "11100100100110110110100111000001",
    "11101111101111100100011110000110",
    "00001111110000011001110111000110",
    "00100100000011001010000111001100",
    "00101101111010010010110001101111",
    "01001010011101001000010010101010",
    "01011100101100001010100111011100",
    "01110110111110011000100011011010",
    "10011000001111100101000101010010",
    "10101000001100011100011001101101",
    "10110000000000110010011111001000",
    "10111111010110010111111111000111",
    "11000110111000000000101111110011",
    "11010101101001111001000101000111",
    "00000110110010100110001101010001",
    "00010100001010010010100101100111",
    "00100111101101110000101010000101",
    "00101110000110110010000100111000",
    "01001101001011000110110111111100",
    "01010011001110000000110100010011",
    "01100101000010100111001101010100",
    "01110110011010100000101010111011",
    "10000001110000101100100100101110",
    "10010010011100100010110010000101",
    "10100010101111111110100010100001",
    "10101000000110100110011001001011",
    "11000010010010111000101101110000",
    "11000111011011000101000110100011",
    "11010001100100101110100000011001",
    "11010110100110010000011000100100",
    "11110100000011100011010110000101",
    "00010000011010101010000001110000",
    "00011001101001001100000100010110",
    "00011110001101110110110000001000",
    "00100111010010000111011101001100",
    "00110100101100001011110010110101",
    "00111001000111000000110010110011",
    "01001110110110001010101001001010",
    "01011011100111001100101001001111",
    "01101000001011100110111111110011",
    "01110100100011111000001011101110",
    "01111000101001010110001101101111",
    "10000100110010000111100000010100",
    "10001100110001110000001000001000",
    "10010000101111101111111111111010",
    "10100100010100000110110011101011",
    "10111110111110011010001111110111",
    "11000110011100010111100011110010"];

func sha224(data) {
    # 1. Encode the input to binary using UTF-8 and append a single '1' to it.
    # 2. Prepend that binary to the message block.
    local message = "";
    local i = 1;
    repeat length $data {
        message &= zfill(base_conv10to(ord($data[i]), B2_DIGITS), 8);
        i++;
    }
    message &= 1;

    # 3. Append the original message length (110000, 48 in decimal) at the end of the message block as a 64-bit big-endian integer.
    local length_int = zfill(base_conv10to(length $data * 8, B2_DIGITS), 64);
    # 4. Add 399 zeros between the encoded message and the length integer so that the message block is a multiple of 512. In this case 48 + 1 + 399 + 64 = 512
    until (length message + 64) % 512 == 0 {
        message &= 0;
    }
    message &= length_int;

    ############################
    # 1. Break the message block into 512-bit chunks. In our case 1 chunk.
    delete sha224_chunks;
    local chunk = "";
    i = 1;
    repeat length message {
        chunk &= message[i];
        if i % 512 == 0 {
            add chunk to sha224_chunks;
            chunk = "";
        }
        i++;
    }

    # 1. Initialize hash value h0 to h7: first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19).
    local h0 = "11000001000001011001111011011000";
    local h1 = "00110110011111001101010100000111";
    local h2 = "00110000011100001101110100010111";
    local h3 = "11110111000011100101100100111001";
    local h4 = "11111111110000000000101100110001";
    local h5 = "01101000010110000001010100010001";
    local h6 = "01100100111110011000111110100111";
    local h7 = "10111110111110100100111110100100";

    # 2. Create a 64-entry message schedule array w[0..63] of 32-bit words.
    local chunk_i = 1;
    repeat length sha224_chunks {
        local chunk = sha224_chunks[chunk_i];

        # 3. Copy 1st chunk into 1st 16 words w[0..15] of the message schedule array.
        delete sha224_words;
        i = 1;
        local word = "";
        repeat 512 {
            word &= chunk[i];
            if length word == 32 {
                add word to sha224_words;
                word = "";
            }
            i++;
        }
        ############################
        # 1. Calculate:
        i = 16;
        until i == 64 {
            local w1 = sha224_words[i - 14];
            local w14 = sha224_words[i - 1];
            # σ0
            local st = bstr_xor(bstr_xor(bstr_rrot(w1, 7), bstr_rrot(w1, 18)), bstr_rshift(w1, 3));
            # σ1
            local s1 = bstr_xor(bstr_xor(bstr_rrot(w14, 17), bstr_rrot(w14, 19)), bstr_rshift(w14, 10));

            # w16 = w0 + σ0 + w9 + σ1
            add _hashlib_truncate32(bstr_add(bstr_add(bstr_add(sha224_words[i - 15], st), sha224_words[i - 6]), s1)) to sha224_words;
            i++;
        }

        ############################
        
        # 3. Initialize working variables to initial hash value:
        local a = h0;
        local b = h1;
        local c = h2;
        local d = h3;
        local e = h4;
        local f = h5;
        local g = h6;
        local h = h7;
        
        i = 1;
        repeat 64 {
            # log (i-1) & ".";
            # log "h=" & h;
            # log "g=" & g;
            # log "f=" & f;
            # log "e=" & e;
            # log "d=" & d;
            # log "c=" & c;
            # log "b=" & b;
            # log "a=" & a;

            # 4. Update working variables as:
            local w0 = sha224_words[i];
            local k0 = sha224_k[i];

            local majority = bstr_xor(bstr_xor(bstr_and(a, b), bstr_and(a, c)), bstr_and(b, c));

            local su0 = bstr_xor(bstr_xor(
                bstr_rrot(a, 2),
                bstr_rrot(a, 13)),
                bstr_rrot(a, 22));
            local su1 = bstr_xor(bstr_xor(
                bstr_rrot(e, 6),
                bstr_rrot(e, 11)),
                bstr_rrot(e, 25));

            local choice = bstr_xor(bstr_and(e, f), bstr_and(bstr_not(e), g));

            local temp2 = _hashlib_truncate32(bstr_add(su0, majority));
            local temp1 = _hashlib_truncate32(bstr_add(bstr_add(bstr_add(bstr_add(h, su1), choice), k0), w0));

            h = g;
            g = f;
            f = e;
            e = _hashlib_truncate32(bstr_add(d, temp1));
            d = c;
            c = b;
            b = a;
            a = _hashlib_truncate32(bstr_add(temp1, temp2));

            # log "Σ1=" & su1;

            # log "Choice=" & choice;
            # log "Temp1=" & temp1;
            
            # log "Σ0=" & su0;
            # log "Temp2=" & temp2;
            # log "majority=" & majority;
            
            # log "Temp1 + Temp2 = " & a;
            # log "d + Temp1 = " & e;

            i++;
        }

        # 2. Add the working variables to the current hash value:
        
        h0 = _hashlib_truncate32(bstr_add(h0, a));
        h1 = _hashlib_truncate32(bstr_add(h1, b));
        h2 = _hashlib_truncate32(bstr_add(h2, c));
        h3 = _hashlib_truncate32(bstr_add(h3, d));
        h4 = _hashlib_truncate32(bstr_add(h4, e));
        h5 = _hashlib_truncate32(bstr_add(h5, f));
        h6 = _hashlib_truncate32(bstr_add(h6, g));
        h7 = _hashlib_truncate32(bstr_add(h7, h));

        chunk_i++;
    }
    # 3. Append hash values to get final digest:
    h0 = _hashlib_truncate32(h0);
    h1 = _hashlib_truncate32(h1);
    h2 = _hashlib_truncate32(h2);
    h3 = _hashlib_truncate32(h3);
    h4 = _hashlib_truncate32(h4);
    h5 = _hashlib_truncate32(h5);
    h6 = _hashlib_truncate32(h6);
    # h7 = _hashlib_truncate32(h7);
    
    h0 = zfill(base_conv(h0, B2_DIGITS, B16_DIGITS), 8);
    h1 = zfill(base_conv(h1, B2_DIGITS, B16_DIGITS), 8);
    h2 = zfill(base_conv(h2, B2_DIGITS, B16_DIGITS), 8);
    h3 = zfill(base_conv(h3, B2_DIGITS, B16_DIGITS), 8);
    h4 = zfill(base_conv(h4, B2_DIGITS, B16_DIGITS), 8);
    h5 = zfill(base_conv(h5, B2_DIGITS, B16_DIGITS), 8);
    h6 = zfill(base_conv(h6, B2_DIGITS, B16_DIGITS), 8);
    # h7 = zfill(base_conv(h7, B2_DIGITS, B16_DIGITS), 8);
    
    return h0 & h1 & h2 & h3 & h4 & h5 & h6;
}
