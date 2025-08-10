# hashlib.gs

> Hashes in goboscript 

This is a hash library which is built for [goboscript](https://github.com/aspizu/goboscript).
It is designed to be used with [inflator](https://github.com/faretek1/inflator).

> [!NOTE]
> This library is WIP

## Credits

- [TheAlgorithms](https://thealgorithms.github.io/Python/autoapi/hashes/index.html)
    - https://github.com/TheAlgorithms/Python/tree/master/hashes
- https://www.metamorphosite.com/one-way-hash-encryption-sha1-data-software
- https://sha256algorithm.com/
- https://github.com/thomdixon/pysha2/tree/master/sha2
- https://www.nic.ad.jp/ja/tech/ipa/RFC3874EN.html


## Installation

Make sure you have inflator installed

`inflate install https://github.com/FAReTek1/hashlib`

add hashlib to your `inflator.toml` config:
```toml
[dependencies]
# ...
hashlib = "https://github.com/FAReTek1/hashlib"
```

## Development

use `inflate install -e .`:

1. clone the respository: `git clone https://github.com/FAReTek1/hashlib`
2. `cd hashlib`
3. `inflate install -e .`
4. `cd test`
5. `inflate`
6. `goboscript build`
7. open `test.sb3`
