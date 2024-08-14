(function() {var type_impls = {
"chacha20poly1305":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-AeadCore-for-ChaChaPoly1305%3CC,+N%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/chacha20poly1305/lib.rs.html#241-248\">source</a><a href=\"#impl-AeadCore-for-ChaChaPoly1305%3CC,+N%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C, N&gt; <a class=\"trait\" href=\"chacha20poly1305/trait.AeadCore.html\" title=\"trait chacha20poly1305::AeadCore\">AeadCore</a> for <a class=\"struct\" href=\"chacha20poly1305/struct.ChaChaPoly1305.html\" title=\"struct chacha20poly1305::ChaChaPoly1305\">ChaChaPoly1305</a>&lt;C, N&gt;<div class=\"where\">where\n    N: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.NonceSize\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.NonceSize\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"chacha20poly1305/trait.AeadCore.html#associatedtype.NonceSize\" class=\"associatedtype\">NonceSize</a> = N</h4></section></summary><div class='docblock'>The length of a nonce.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.TagSize\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.TagSize\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"chacha20poly1305/trait.AeadCore.html#associatedtype.TagSize\" class=\"associatedtype\">TagSize</a> = <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a>, <a class=\"struct\" href=\"chacha20poly1305/consts/struct.B1.html\" title=\"struct chacha20poly1305::consts::B1\">B1</a>&gt;, <a class=\"struct\" href=\"chacha20poly1305/consts/struct.B0.html\" title=\"struct chacha20poly1305::consts::B0\">B0</a>&gt;, <a class=\"struct\" href=\"chacha20poly1305/consts/struct.B0.html\" title=\"struct chacha20poly1305::consts::B0\">B0</a>&gt;, <a class=\"struct\" href=\"chacha20poly1305/consts/struct.B0.html\" title=\"struct chacha20poly1305::consts::B0\">B0</a>&gt;, <a class=\"struct\" href=\"chacha20poly1305/consts/struct.B0.html\" title=\"struct chacha20poly1305::consts::B0\">B0</a>&gt;</h4></section></summary><div class='docblock'>The maximum length of the nonce.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.CiphertextOverhead\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.CiphertextOverhead\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"chacha20poly1305/trait.AeadCore.html#associatedtype.CiphertextOverhead\" class=\"associatedtype\">CiphertextOverhead</a> = <a class=\"struct\" href=\"typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a></h4></section></summary><div class='docblock'>The upper bound amount of additional space required to support a\nciphertext vs. a plaintext.</div></details></div></details>","AeadCore","chacha20poly1305::ChaCha20Poly1305","chacha20poly1305::XChaCha20Poly1305","chacha20poly1305::ChaCha8Poly1305","chacha20poly1305::ChaCha12Poly1305","chacha20poly1305::XChaCha8Poly1305","chacha20poly1305::XChaCha12Poly1305"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-AeadInPlace-for-ChaChaPoly1305%3CC,+N%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/chacha20poly1305/lib.rs.html#250-277\">source</a><a href=\"#impl-AeadInPlace-for-ChaChaPoly1305%3CC,+N%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C, N&gt; <a class=\"trait\" href=\"chacha20poly1305/trait.AeadInPlace.html\" title=\"trait chacha20poly1305::AeadInPlace\">AeadInPlace</a> for <a class=\"struct\" href=\"chacha20poly1305/struct.ChaChaPoly1305.html\" title=\"struct chacha20poly1305::ChaChaPoly1305\">ChaChaPoly1305</a>&lt;C, N&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"crypto_common/trait.KeyIvInit.html\" title=\"trait crypto_common::KeyIvInit\">KeyIvInit</a>&lt;KeySize = <a class=\"type\" href=\"chacha20poly1305/consts/type.U32.html\" title=\"type chacha20poly1305::consts::U32\">U32</a>, IvSize = N&gt; + <a class=\"trait\" href=\"cipher/stream/trait.StreamCipher.html\" title=\"trait cipher::stream::StreamCipher\">StreamCipher</a> + <a class=\"trait\" href=\"cipher/stream/trait.StreamCipherSeek.html\" title=\"trait cipher::stream::StreamCipherSeek\">StreamCipherSeek</a>,\n    N: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.encrypt_in_place_detached\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/chacha20poly1305/lib.rs.html#255-262\">source</a><a href=\"#method.encrypt_in_place_detached\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"chacha20poly1305/trait.AeadInPlace.html#tymethod.encrypt_in_place_detached\" class=\"fn\">encrypt_in_place_detached</a>(\n    &amp;self,\n    nonce: &amp;<a class=\"type\" href=\"aead/type.Nonce.html\" title=\"type aead::Nonce\">Nonce</a>&lt;Self&gt;,\n    associated_data: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>],\n    buffer: &amp;mut [<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>],\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.80.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"type\" href=\"chacha20poly1305/type.Tag.html\" title=\"type chacha20poly1305::Tag\">Tag</a>, <a class=\"struct\" href=\"chacha20poly1305/struct.Error.html\" title=\"struct chacha20poly1305::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Encrypt the data in-place, returning the authentication tag</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.decrypt_in_place_detached\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/chacha20poly1305/lib.rs.html#264-276\">source</a><a href=\"#method.decrypt_in_place_detached\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"chacha20poly1305/trait.AeadInPlace.html#tymethod.decrypt_in_place_detached\" class=\"fn\">decrypt_in_place_detached</a>(\n    &amp;self,\n    nonce: &amp;<a class=\"type\" href=\"aead/type.Nonce.html\" title=\"type aead::Nonce\">Nonce</a>&lt;Self&gt;,\n    associated_data: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>],\n    buffer: &amp;mut [<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>],\n    tag: &amp;<a class=\"type\" href=\"chacha20poly1305/type.Tag.html\" title=\"type chacha20poly1305::Tag\">Tag</a>,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.80.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"chacha20poly1305/struct.Error.html\" title=\"struct chacha20poly1305::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Decrypt the message in-place, returning an error in the event the provided\nauthentication tag does not match the given ciphertext (i.e. ciphertext\nis modified/unauthentic)</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.encrypt_in_place\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/aead/lib.rs.html#280-285\">source</a><a href=\"#method.encrypt_in_place\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"chacha20poly1305/trait.AeadInPlace.html#method.encrypt_in_place\" class=\"fn\">encrypt_in_place</a>(\n    &amp;self,\n    nonce: &amp;<a class=\"struct\" href=\"generic_array/struct.GenericArray.html\" title=\"struct generic_array::GenericArray\">GenericArray</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>, Self::<a class=\"associatedtype\" href=\"chacha20poly1305/trait.AeadCore.html#associatedtype.NonceSize\" title=\"type chacha20poly1305::AeadCore::NonceSize\">NonceSize</a>&gt;,\n    associated_data: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>],\n    buffer: &amp;mut dyn <a class=\"trait\" href=\"aead/trait.Buffer.html\" title=\"trait aead::Buffer\">Buffer</a>,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.80.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"chacha20poly1305/struct.Error.html\" title=\"struct chacha20poly1305::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Encrypt the given buffer containing a plaintext message in-place. <a href=\"chacha20poly1305/trait.AeadInPlace.html#method.encrypt_in_place\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.decrypt_in_place\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/aead/lib.rs.html#304-309\">source</a><a href=\"#method.decrypt_in_place\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"chacha20poly1305/trait.AeadInPlace.html#method.decrypt_in_place\" class=\"fn\">decrypt_in_place</a>(\n    &amp;self,\n    nonce: &amp;<a class=\"struct\" href=\"generic_array/struct.GenericArray.html\" title=\"struct generic_array::GenericArray\">GenericArray</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>, Self::<a class=\"associatedtype\" href=\"chacha20poly1305/trait.AeadCore.html#associatedtype.NonceSize\" title=\"type chacha20poly1305::AeadCore::NonceSize\">NonceSize</a>&gt;,\n    associated_data: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>],\n    buffer: &amp;mut dyn <a class=\"trait\" href=\"aead/trait.Buffer.html\" title=\"trait aead::Buffer\">Buffer</a>,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.80.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"chacha20poly1305/struct.Error.html\" title=\"struct chacha20poly1305::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Decrypt the message in-place, returning an error in the event the\nprovided authentication tag does not match the given ciphertext. <a href=\"chacha20poly1305/trait.AeadInPlace.html#method.decrypt_in_place\">Read more</a></div></details></div></details>","AeadInPlace","chacha20poly1305::ChaCha20Poly1305","chacha20poly1305::XChaCha20Poly1305","chacha20poly1305::ChaCha8Poly1305","chacha20poly1305::ChaCha12Poly1305","chacha20poly1305::XChaCha8Poly1305","chacha20poly1305::XChaCha12Poly1305"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-ChaChaPoly1305%3CC,+N%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/chacha20poly1305/lib.rs.html#279-290\">source</a><a href=\"#impl-Clone-for-ChaChaPoly1305%3CC,+N%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C, N&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.80.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"chacha20poly1305/struct.ChaChaPoly1305.html\" title=\"struct chacha20poly1305::ChaChaPoly1305\">ChaChaPoly1305</a>&lt;C, N&gt;<div class=\"where\">where\n    N: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/chacha20poly1305/lib.rs.html#283-289\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.80.1/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; Self</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.80.1/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.80.1/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.80.1/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.80.1/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","chacha20poly1305::ChaCha20Poly1305","chacha20poly1305::XChaCha20Poly1305","chacha20poly1305::ChaCha8Poly1305","chacha20poly1305::ChaCha12Poly1305","chacha20poly1305::XChaCha8Poly1305","chacha20poly1305::XChaCha12Poly1305"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Drop-for-ChaChaPoly1305%3CC,+N%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/chacha20poly1305/lib.rs.html#292-299\">source</a><a href=\"#impl-Drop-for-ChaChaPoly1305%3CC,+N%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C, N&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.80.1/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"chacha20poly1305/struct.ChaChaPoly1305.html\" title=\"struct chacha20poly1305::ChaChaPoly1305\">ChaChaPoly1305</a>&lt;C, N&gt;<div class=\"where\">where\n    N: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.drop\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/chacha20poly1305/lib.rs.html#296-298\">source</a><a href=\"#method.drop\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.80.1/core/ops/drop/trait.Drop.html#tymethod.drop\" class=\"fn\">drop</a>(&amp;mut self)</h4></section></summary><div class='docblock'>Executes the destructor for this type. <a href=\"https://doc.rust-lang.org/1.80.1/core/ops/drop/trait.Drop.html#tymethod.drop\">Read more</a></div></details></div></details>","Drop","chacha20poly1305::ChaCha20Poly1305","chacha20poly1305::XChaCha20Poly1305","chacha20poly1305::ChaCha8Poly1305","chacha20poly1305::ChaCha12Poly1305","chacha20poly1305::XChaCha8Poly1305","chacha20poly1305::XChaCha12Poly1305"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-KeyInit-for-ChaChaPoly1305%3CC,+N%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/chacha20poly1305/lib.rs.html#227-239\">source</a><a href=\"#impl-KeyInit-for-ChaChaPoly1305%3CC,+N%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C, N&gt; <a class=\"trait\" href=\"chacha20poly1305/trait.KeyInit.html\" title=\"trait chacha20poly1305::KeyInit\">KeyInit</a> for <a class=\"struct\" href=\"chacha20poly1305/struct.ChaChaPoly1305.html\" title=\"struct chacha20poly1305::ChaChaPoly1305\">ChaChaPoly1305</a>&lt;C, N&gt;<div class=\"where\">where\n    N: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.new\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/chacha20poly1305/lib.rs.html#232-238\">source</a><a href=\"#method.new\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"chacha20poly1305/trait.KeyInit.html#tymethod.new\" class=\"fn\">new</a>(key: &amp;<a class=\"type\" href=\"chacha20poly1305/type.Key.html\" title=\"type chacha20poly1305::Key\">Key</a>) -&gt; Self</h4></section></summary><div class='docblock'>Create new value from fixed size key.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.new_from_slice\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/crypto_common/lib.rs.html#129\">source</a><a href=\"#method.new_from_slice\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"chacha20poly1305/trait.KeyInit.html#method.new_from_slice\" class=\"fn\">new_from_slice</a>(key: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>]) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.80.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, <a class=\"struct\" href=\"crypto_common/struct.InvalidLength.html\" title=\"struct crypto_common::InvalidLength\">InvalidLength</a>&gt;</h4></section></summary><div class='docblock'>Create new value from variable size key.</div></details></div></details>","KeyInit","chacha20poly1305::ChaCha20Poly1305","chacha20poly1305::XChaCha20Poly1305","chacha20poly1305::ChaCha8Poly1305","chacha20poly1305::ChaCha12Poly1305","chacha20poly1305::XChaCha8Poly1305","chacha20poly1305::XChaCha12Poly1305"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-KeySizeUser-for-ChaChaPoly1305%3CC,+N%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/chacha20poly1305/lib.rs.html#220-225\">source</a><a href=\"#impl-KeySizeUser-for-ChaChaPoly1305%3CC,+N%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C, N&gt; <a class=\"trait\" href=\"chacha20poly1305/trait.KeySizeUser.html\" title=\"trait chacha20poly1305::KeySizeUser\">KeySizeUser</a> for <a class=\"struct\" href=\"chacha20poly1305/struct.ChaChaPoly1305.html\" title=\"struct chacha20poly1305::ChaChaPoly1305\">ChaChaPoly1305</a>&lt;C, N&gt;<div class=\"where\">where\n    N: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.KeySize\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.KeySize\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"chacha20poly1305/trait.KeySizeUser.html#associatedtype.KeySize\" class=\"associatedtype\">KeySize</a> = <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a>, <a class=\"struct\" href=\"chacha20poly1305/consts/struct.B1.html\" title=\"struct chacha20poly1305::consts::B1\">B1</a>&gt;, <a class=\"struct\" href=\"chacha20poly1305/consts/struct.B0.html\" title=\"struct chacha20poly1305::consts::B0\">B0</a>&gt;, <a class=\"struct\" href=\"chacha20poly1305/consts/struct.B0.html\" title=\"struct chacha20poly1305::consts::B0\">B0</a>&gt;, <a class=\"struct\" href=\"chacha20poly1305/consts/struct.B0.html\" title=\"struct chacha20poly1305::consts::B0\">B0</a>&gt;, <a class=\"struct\" href=\"chacha20poly1305/consts/struct.B0.html\" title=\"struct chacha20poly1305::consts::B0\">B0</a>&gt;, <a class=\"struct\" href=\"chacha20poly1305/consts/struct.B0.html\" title=\"struct chacha20poly1305::consts::B0\">B0</a>&gt;</h4></section></summary><div class='docblock'>Key size in bytes.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.key_size\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/crypto_common/lib.rs.html#85\">source</a><a href=\"#method.key_size\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"chacha20poly1305/trait.KeySizeUser.html#method.key_size\" class=\"fn\">key_size</a>() -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.usize.html\">usize</a></h4></section></summary><div class='docblock'>Return key size in bytes.</div></details></div></details>","KeySizeUser","chacha20poly1305::ChaCha20Poly1305","chacha20poly1305::XChaCha20Poly1305","chacha20poly1305::ChaCha8Poly1305","chacha20poly1305::ChaCha12Poly1305","chacha20poly1305::XChaCha8Poly1305","chacha20poly1305::XChaCha12Poly1305"],["<section id=\"impl-ZeroizeOnDrop-for-ChaChaPoly1305%3CC,+N%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/chacha20poly1305/lib.rs.html#301\">source</a><a href=\"#impl-ZeroizeOnDrop-for-ChaChaPoly1305%3CC,+N%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C, N: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>&gt;&gt; <a class=\"trait\" href=\"zeroize/trait.ZeroizeOnDrop.html\" title=\"trait zeroize::ZeroizeOnDrop\">ZeroizeOnDrop</a> for <a class=\"struct\" href=\"chacha20poly1305/struct.ChaChaPoly1305.html\" title=\"struct chacha20poly1305::ChaChaPoly1305\">ChaChaPoly1305</a>&lt;C, N&gt;</h3></section>","ZeroizeOnDrop","chacha20poly1305::ChaCha20Poly1305","chacha20poly1305::XChaCha20Poly1305","chacha20poly1305::ChaCha8Poly1305","chacha20poly1305::ChaCha12Poly1305","chacha20poly1305::XChaCha8Poly1305","chacha20poly1305::XChaCha12Poly1305"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()