(function() {var type_impls = {
"p256":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Drop-for-SharedSecret%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#214\">source</a><a href=\"#impl-Drop-for-SharedSecret%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.80.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"elliptic_curve/ecdh/struct.SharedSecret.html\" title=\"struct elliptic_curve::ecdh::SharedSecret\">SharedSecret</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/weierstrass/trait.Curve.html\" title=\"trait elliptic_curve::weierstrass::Curve\">Curve</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.drop\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#215\">source</a><a href=\"#method.drop\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.80.0/core/ops/drop/trait.Drop.html#tymethod.drop\" class=\"fn\">drop</a>(&amp;mut self)</h4></section></summary><div class='docblock'>Executes the destructor for this type. <a href=\"https://doc.rust-lang.org/1.80.0/core/ops/drop/trait.Drop.html#tymethod.drop\">Read more</a></div></details></div></details>","Drop","p256::ecdh::SharedSecret"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3CGenericArray%3Cu8,+%3C%3CC+as+Curve%3E::UInt+as+ArrayEncoding%3E::ByteSize%3E%3E-for-SharedSecret%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#196\">source</a><a href=\"#impl-From%3CGenericArray%3Cu8,+%3C%3CC+as+Curve%3E::UInt+as+ArrayEncoding%3E::ByteSize%3E%3E-for-SharedSecret%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.80.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"generic_array/struct.GenericArray.html\" title=\"struct generic_array::GenericArray\">GenericArray</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.0/core/primitive.u8.html\">u8</a>, &lt;&lt;C as <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>&gt;::<a class=\"associatedtype\" href=\"elliptic_curve/trait.Curve.html#associatedtype.UInt\" title=\"type elliptic_curve::Curve::UInt\">UInt</a> as <a class=\"trait\" href=\"crypto_bigint/array/trait.ArrayEncoding.html\" title=\"trait crypto_bigint::array::ArrayEncoding\">ArrayEncoding</a>&gt;::<a class=\"associatedtype\" href=\"crypto_bigint/array/trait.ArrayEncoding.html#associatedtype.ByteSize\" title=\"type crypto_bigint::array::ArrayEncoding::ByteSize\">ByteSize</a>&gt;&gt; for <a class=\"struct\" href=\"elliptic_curve/ecdh/struct.SharedSecret.html\" title=\"struct elliptic_curve::ecdh::SharedSecret\">SharedSecret</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/weierstrass/trait.Curve.html\" title=\"trait elliptic_curve::weierstrass::Curve\">Curve</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#203\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.80.0/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(\n    secret_bytes: <a class=\"struct\" href=\"generic_array/struct.GenericArray.html\" title=\"struct generic_array::GenericArray\">GenericArray</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.0/core/primitive.u8.html\">u8</a>, &lt;&lt;C as <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>&gt;::<a class=\"associatedtype\" href=\"elliptic_curve/trait.Curve.html#associatedtype.UInt\" title=\"type elliptic_curve::Curve::UInt\">UInt</a> as <a class=\"trait\" href=\"crypto_bigint/array/trait.ArrayEncoding.html\" title=\"trait crypto_bigint::array::ArrayEncoding\">ArrayEncoding</a>&gt;::<a class=\"associatedtype\" href=\"crypto_bigint/array/trait.ArrayEncoding.html#associatedtype.ByteSize\" title=\"type crypto_bigint::array::ArrayEncoding::ByteSize\">ByteSize</a>&gt;,\n) -&gt; <a class=\"struct\" href=\"elliptic_curve/ecdh/struct.SharedSecret.html\" title=\"struct elliptic_curve::ecdh::SharedSecret\">SharedSecret</a>&lt;C&gt;</h4></section></summary><div class=\"docblock\"><p>NOTE: this impl is intended to be used by curve implementations to\ninstantiate a <a href=\"elliptic_curve/ecdh/struct.SharedSecret.html\" title=\"struct elliptic_curve::ecdh::SharedSecret\"><code>SharedSecret</code></a> value from their respective\n<a href=\"elliptic_curve/type.AffinePoint.html\" title=\"type elliptic_curve::AffinePoint\"><code>AffinePoint</code></a> type.</p>\n<p>Curve implementations should provide the field element representing\nthe affine x-coordinate as <code>secret_bytes</code>.</p>\n</div></details></div></details>","From<GenericArray<u8, <<C as Curve>::UInt as ArrayEncoding>::ByteSize>>","p256::ecdh::SharedSecret"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-SharedSecret%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#184\">source</a><a href=\"#impl-SharedSecret%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"struct\" href=\"elliptic_curve/ecdh/struct.SharedSecret.html\" title=\"struct elliptic_curve::ecdh::SharedSecret\">SharedSecret</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/weierstrass/trait.Curve.html\" title=\"trait elliptic_curve::weierstrass::Curve\">Curve</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.as_bytes\" class=\"method\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#191\">source</a><h4 class=\"code-header\">pub fn <a href=\"elliptic_curve/ecdh/struct.SharedSecret.html#tymethod.as_bytes\" class=\"fn\">as_bytes</a>(\n    &amp;self,\n) -&gt; &amp;<a class=\"struct\" href=\"generic_array/struct.GenericArray.html\" title=\"struct generic_array::GenericArray\">GenericArray</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.0/core/primitive.u8.html\">u8</a>, &lt;&lt;C as <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>&gt;::<a class=\"associatedtype\" href=\"elliptic_curve/trait.Curve.html#associatedtype.UInt\" title=\"type elliptic_curve::Curve::UInt\">UInt</a> as <a class=\"trait\" href=\"crypto_bigint/array/trait.ArrayEncoding.html\" title=\"trait crypto_bigint::array::ArrayEncoding\">ArrayEncoding</a>&gt;::<a class=\"associatedtype\" href=\"crypto_bigint/array/trait.ArrayEncoding.html#associatedtype.ByteSize\" title=\"type crypto_bigint::array::ArrayEncoding::ByteSize\">ByteSize</a>&gt;</h4></section></summary><div class=\"docblock\"><p>Shared secret value, serialized as bytes.</p>\n<p>As noted in the comments for this struct, this value is non-uniform and\nshould not be used directly as a symmetric encryption key, but instead\nas input to a KDF (or failing that, a hash function) used to produce\na symmetric key.</p>\n</div></details></div></details>",0,"p256::ecdh::SharedSecret"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Zeroize-for-SharedSecret%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#208\">source</a><a href=\"#impl-Zeroize-for-SharedSecret%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"zeroize/trait.Zeroize.html\" title=\"trait zeroize::Zeroize\">Zeroize</a> for <a class=\"struct\" href=\"elliptic_curve/ecdh/struct.SharedSecret.html\" title=\"struct elliptic_curve::ecdh::SharedSecret\">SharedSecret</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/weierstrass/trait.Curve.html\" title=\"trait elliptic_curve::weierstrass::Curve\">Curve</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.zeroize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#209\">source</a><a href=\"#method.zeroize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"zeroize/trait.Zeroize.html#tymethod.zeroize\" class=\"fn\">zeroize</a>(&amp;mut self)</h4></section></summary><div class='docblock'>Zero out this object from memory using Rust intrinsics which ensure the\nzeroization operation is not “optimized away” by the compiler.</div></details></div></details>","Zeroize","p256::ecdh::SharedSecret"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()