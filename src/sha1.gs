# Reference: https://www.metamorphosite.com/one-way-hash-encryption-sha1-data-software
# This only works on ASCII

list sha1_chunks;
list sha1_words;

func sha1(data) {
    # Step 0
    local h0 = "01100111010001010010001100000001";
    local h1 = "11101111110011011010101110001001";
    local h2 = "10011000101110101101110011111110";
    local h3 = "00010000001100100101010001110110";
    local h4 = "11000011110100101110000111110000";
    
    # Step 1
    # Step 2
    # Step 3
    local message = "";
    local i = 1;
    repeat length $data {
        local ascii_code = ord($data[i]);
        local ascii_binary_repr = base_conv10to(ascii_code, B2_DIGITS);
        message &= zfill(ascii_binary_repr, 8);
        i++;
    }
    
    # Step 5
    message &= 1;

    # Step 6
    until length message % 512 == 448 {
        message &= 0;
    }
    
    # Step 6.1
    message &= zfill(base_conv10to(length $data * 8, B2_DIGITS), 64);

    # Step 7
    delete sha1_chunks;
    i = 1;
    repeat length message / 512 {
        add slice(message, i, i + 511) to sha1_chunks;
        i += 512;
    }

    local chunk_i = 0;
    repeat length sha1_chunks {
        chunk_i++;
        local chunk = sha1_chunks[chunk_i];
        
        # Step 8
        delete sha1_words;
        i = 1;
        repeat 16 {
            add slice(chunk, i, i + 32) to sha1_words;
            i += 32;
        }

        # Step 9.1
        i = 17;
        repeat 80 - 16 {
            local w13 = sha1_words[i - 3];
            local w8 = sha1_words[i - 8];
            local w2 = sha1_words[i - 14];
            local w0 = sha1_words[i - 16];

            local word = bstr_xor(w13, w8);
            word = bstr_xor(word, w2);
            word = bstr_xor(word, w0);

            # Step 9.2
            word = slice(word, 2, length word) & word[1];

            add word to sha1_words;

            i++;
        }
    }
}

func bstr_xor(b1, b2) {
    local out = "";
    local i = 1;
    repeat length $b1 {
        out &= ($b1[i] != $b2[i])+"";
        i++;
    }
    return out;
}
