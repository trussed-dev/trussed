(function() {
    var type_impls = Object.fromEntries([["p256",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-SecretKey%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#73\">source</a><a href=\"#impl-Clone-for-SecretKey%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#73\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.83.0/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.83.0/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.83.0/src/core/clone.rs.html#174\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.83.0/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: &amp;Self)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.83.0/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","p256::SecretKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-SecretKey%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#240-242\">source</a><a href=\"#impl-Debug-for-SecretKey%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#244\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.83.0/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/1.83.0/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.83.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/1.83.0/core/fmt/struct.Error.html\" title=\"struct core::fmt::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/1.83.0/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","p256::SecretKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Drop-for-SecretKey%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#250-252\">source</a><a href=\"#impl-Drop-for-SecretKey%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.drop\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#254\">source</a><a href=\"#method.drop\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.83.0/core/ops/drop/trait.Drop.html#tymethod.drop\" class=\"fn\">drop</a>(&amp;mut self)</h4></section></summary><div class='docblock'>Executes the destructor for this type. <a href=\"https://doc.rust-lang.org/1.83.0/core/ops/drop/trait.Drop.html#tymethod.drop\">Read more</a></div></details></div></details>","Drop","p256::SecretKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3C%26NonZeroScalar%3CC%3E%3E-for-SecretKey%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#218-220\">source</a><a href=\"#impl-From%3C%26NonZeroScalar%3CC%3E%3E-for-SecretKey%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"elliptic_curve/scalar/non_zero/struct.NonZeroScalar.html\" title=\"struct elliptic_curve::scalar::non_zero::NonZeroScalar\">NonZeroScalar</a>&lt;C&gt;&gt; for <a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a> + <a class=\"trait\" href=\"elliptic_curve/arithmetic/trait.ProjectiveArithmetic.html\" title=\"trait elliptic_curve::arithmetic::ProjectiveArithmetic\">ProjectiveArithmetic</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#222\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.83.0/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(scalar: &amp;<a class=\"struct\" href=\"elliptic_curve/scalar/non_zero/struct.NonZeroScalar.html\" title=\"struct elliptic_curve::scalar::non_zero::NonZeroScalar\">NonZeroScalar</a>&lt;C&gt;) -&gt; <a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;</h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<&NonZeroScalar<C>>","p256::SecretKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3CNonZeroScalar%3CC%3E%3E-for-SecretKey%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#207-209\">source</a><a href=\"#impl-From%3CNonZeroScalar%3CC%3E%3E-for-SecretKey%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"elliptic_curve/scalar/non_zero/struct.NonZeroScalar.html\" title=\"struct elliptic_curve::scalar::non_zero::NonZeroScalar\">NonZeroScalar</a>&lt;C&gt;&gt; for <a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a> + <a class=\"trait\" href=\"elliptic_curve/arithmetic/trait.ProjectiveArithmetic.html\" title=\"trait elliptic_curve::arithmetic::ProjectiveArithmetic\">ProjectiveArithmetic</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#211\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.83.0/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(scalar: <a class=\"struct\" href=\"elliptic_curve/scalar/non_zero/struct.NonZeroScalar.html\" title=\"struct elliptic_curve::scalar::non_zero::NonZeroScalar\">NonZeroScalar</a>&lt;C&gt;) -&gt; <a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;</h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<NonZeroScalar<C>>","p256::SecretKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-SecretKey%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#79-81\">source</a><a href=\"#impl-SecretKey%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.random\" class=\"method\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#86-89\">source</a><h4 class=\"code-header\">pub fn <a href=\"elliptic_curve/secret_key/struct.SecretKey.html#tymethod.random\" class=\"fn\">random</a>(rng: impl <a class=\"trait\" href=\"rand_core/trait.CryptoRng.html\" title=\"trait rand_core::CryptoRng\">CryptoRng</a> + <a class=\"trait\" href=\"rand_core/trait.RngCore.html\" title=\"trait rand_core::RngCore\">RngCore</a>) -&gt; <a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/arithmetic/trait.ProjectiveArithmetic.html\" title=\"trait elliptic_curve::arithmetic::ProjectiveArithmetic\">ProjectiveArithmetic</a>,\n    &lt;C as <a class=\"trait\" href=\"elliptic_curve/arithmetic/trait.ScalarArithmetic.html\" title=\"trait elliptic_curve::arithmetic::ScalarArithmetic\">ScalarArithmetic</a>&gt;::<a class=\"associatedtype\" href=\"elliptic_curve/arithmetic/trait.ScalarArithmetic.html#associatedtype.Scalar\" title=\"type elliptic_curve::arithmetic::ScalarArithmetic::Scalar\">Scalar</a>: <a class=\"trait\" href=\"zeroize/trait.Zeroize.html\" title=\"trait zeroize::Zeroize\">Zeroize</a>,</div></h4></section></summary><div class=\"docblock\"><p>Generate a random <a href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\"><code>SecretKey</code></a></p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.new\" class=\"method\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#97\">source</a><h4 class=\"code-header\">pub fn <a href=\"elliptic_curve/secret_key/struct.SecretKey.html#tymethod.new\" class=\"fn\">new</a>(scalar: <a class=\"struct\" href=\"elliptic_curve/scalar/bytes/struct.ScalarBytes.html\" title=\"struct elliptic_curve::scalar::bytes::ScalarBytes\">ScalarBytes</a>&lt;C&gt;) -&gt; <a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;</h4></section></summary><div class=\"docblock\"><p>Create a new secret key from a serialized scalar value</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.from_bytes\" class=\"method\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#102\">source</a><h4 class=\"code-header\">pub fn <a href=\"elliptic_curve/secret_key/struct.SecretKey.html#tymethod.from_bytes\" class=\"fn\">from_bytes</a>(bytes: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/convert/trait.AsRef.html\" title=\"trait core::convert::AsRef\">AsRef</a>&lt;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.u8.html\">u8</a>]&gt;) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.83.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;, <a class=\"struct\" href=\"elliptic_curve/error/struct.Error.html\" title=\"struct elliptic_curve::error::Error\">Error</a>&gt;</h4></section></summary><div class=\"docblock\"><p>Deserialize raw private scalar as a big endian integer</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.to_bytes\" class=\"method\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#113\">source</a><h4 class=\"code-header\">pub fn <a href=\"elliptic_curve/secret_key/struct.SecretKey.html#tymethod.to_bytes\" class=\"fn\">to_bytes</a>(\n    &amp;self,\n) -&gt; <a class=\"struct\" href=\"generic_array/struct.GenericArray.html\" title=\"struct generic_array::GenericArray\">GenericArray</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.u8.html\">u8</a>, &lt;&lt;C as <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>&gt;::<a class=\"associatedtype\" href=\"elliptic_curve/trait.Curve.html#associatedtype.UInt\" title=\"type elliptic_curve::Curve::UInt\">UInt</a> as <a class=\"trait\" href=\"crypto_bigint/array/trait.ArrayEncoding.html\" title=\"trait crypto_bigint::array::ArrayEncoding\">ArrayEncoding</a>&gt;::<a class=\"associatedtype\" href=\"crypto_bigint/array/trait.ArrayEncoding.html#associatedtype.ByteSize\" title=\"type crypto_bigint::array::ArrayEncoding::ByteSize\">ByteSize</a>&gt;</h4></section></summary><div class=\"docblock\"><p>Expose the byte serialization of the value this <a href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\"><code>SecretKey</code></a> wraps</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.as_scalar_bytes\" class=\"method\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#124\">source</a><h4 class=\"code-header\">pub fn <a href=\"elliptic_curve/secret_key/struct.SecretKey.html#tymethod.as_scalar_bytes\" class=\"fn\">as_scalar_bytes</a>(&amp;self) -&gt; &amp;<a class=\"struct\" href=\"elliptic_curve/scalar/bytes/struct.ScalarBytes.html\" title=\"struct elliptic_curve::scalar::bytes::ScalarBytes\">ScalarBytes</a>&lt;C&gt;</h4></section></summary><div class=\"docblock\"><p>Borrow the inner secret <a href=\"elliptic_curve/scalar/bytes/struct.ScalarBytes.html\" title=\"struct elliptic_curve::scalar::bytes::ScalarBytes\"><code>ScalarBytes</code></a> value.</p>\n<h5 id=\"warning\"><a class=\"doc-anchor\" href=\"#warning\">§</a>Warning</h5>\n<p>This value is key material.</p>\n<p>Please treat it with the care it deserves!</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.to_secret_scalar\" class=\"method\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#131-134\">source</a><h4 class=\"code-header\">pub fn <a href=\"elliptic_curve/secret_key/struct.SecretKey.html#tymethod.to_secret_scalar\" class=\"fn\">to_secret_scalar</a>(&amp;self) -&gt; <a class=\"struct\" href=\"elliptic_curve/scalar/non_zero/struct.NonZeroScalar.html\" title=\"struct elliptic_curve::scalar::non_zero::NonZeroScalar\">NonZeroScalar</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a> + <a class=\"trait\" href=\"elliptic_curve/arithmetic/trait.ProjectiveArithmetic.html\" title=\"trait elliptic_curve::arithmetic::ProjectiveArithmetic\">ProjectiveArithmetic</a>,\n    &lt;C as <a class=\"trait\" href=\"elliptic_curve/arithmetic/trait.ScalarArithmetic.html\" title=\"trait elliptic_curve::arithmetic::ScalarArithmetic\">ScalarArithmetic</a>&gt;::<a class=\"associatedtype\" href=\"elliptic_curve/arithmetic/trait.ScalarArithmetic.html#associatedtype.Scalar\" title=\"type elliptic_curve::arithmetic::ScalarArithmetic::Scalar\">Scalar</a>: <a class=\"trait\" href=\"zeroize/trait.Zeroize.html\" title=\"trait zeroize::Zeroize\">Zeroize</a>,</div></h4></section></summary><div class=\"docblock\"><p>Get the secret scalar value for this key..</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.public_key\" class=\"method\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#142-145\">source</a><h4 class=\"code-header\">pub fn <a href=\"elliptic_curve/secret_key/struct.SecretKey.html#tymethod.public_key\" class=\"fn\">public_key</a>(&amp;self) -&gt; <a class=\"struct\" href=\"elliptic_curve/public_key/struct.PublicKey.html\" title=\"struct elliptic_curve::public_key::PublicKey\">PublicKey</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/weierstrass/trait.Curve.html\" title=\"trait elliptic_curve::weierstrass::Curve\">Curve</a> + <a class=\"trait\" href=\"elliptic_curve/arithmetic/trait.ProjectiveArithmetic.html\" title=\"trait elliptic_curve::arithmetic::ProjectiveArithmetic\">ProjectiveArithmetic</a>,\n    &lt;C as <a class=\"trait\" href=\"elliptic_curve/arithmetic/trait.ScalarArithmetic.html\" title=\"trait elliptic_curve::arithmetic::ScalarArithmetic\">ScalarArithmetic</a>&gt;::<a class=\"associatedtype\" href=\"elliptic_curve/arithmetic/trait.ScalarArithmetic.html#associatedtype.Scalar\" title=\"type elliptic_curve::arithmetic::ScalarArithmetic::Scalar\">Scalar</a>: <a class=\"trait\" href=\"zeroize/trait.Zeroize.html\" title=\"trait zeroize::Zeroize\">Zeroize</a>,</div></h4></section></summary><div class=\"docblock\"><p>Get the <a href=\"elliptic_curve/public_key/struct.PublicKey.html\" title=\"struct elliptic_curve::public_key::PublicKey\"><code>PublicKey</code></a> which corresponds to this secret key</p>\n</div></details></div></details>",0,"p256::SecretKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-TryFrom%3C%26%5Bu8%5D%3E-for-SecretKey%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#229-231\">source</a><a href=\"#impl-TryFrom%3C%26%5Bu8%5D%3E-for-SecretKey%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Error\" class=\"associatedtype trait-impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#233\">source</a><a href=\"#associatedtype.Error\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"https://doc.rust-lang.org/1.83.0/core/convert/trait.TryFrom.html#associatedtype.Error\" class=\"associatedtype\">Error</a> = <a class=\"struct\" href=\"elliptic_curve/error/struct.Error.html\" title=\"struct elliptic_curve::error::Error\">Error</a></h4></section></summary><div class='docblock'>The type returned in the event of a conversion error.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.try_from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/secret_key.rs.html#235\">source</a><a href=\"#method.try_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.83.0/core/convert/trait.TryFrom.html#tymethod.try_from\" class=\"fn\">try_from</a>(slice: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.u8.html\">u8</a>]) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.83.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"struct\" href=\"elliptic_curve/secret_key/struct.SecretKey.html\" title=\"struct elliptic_curve::secret_key::SecretKey\">SecretKey</a>&lt;C&gt;, <a class=\"struct\" href=\"elliptic_curve/error/struct.Error.html\" title=\"struct elliptic_curve::error::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Performs the conversion.</div></details></div></details>","TryFrom<&[u8]>","p256::SecretKey"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[22731]}