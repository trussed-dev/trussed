(function() {
    var implementors = Object.fromEntries([["heapless",[["impl&lt;'a, K, V, S, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.Extend.html\" title=\"trait core::iter::traits::collect::Extend\">Extend</a>&lt;(<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.reference.html\">&amp;'a K</a>, <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.reference.html\">&amp;'a V</a>)&gt; for <a class=\"struct\" href=\"heapless/struct.IndexMap.html\" title=\"struct heapless::IndexMap\">IndexMap</a>&lt;K, V, S, N&gt;<div class=\"where\">where\n    K: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"hash32/trait.Hash.html\" title=\"trait hash32::Hash\">Hash</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>,\n    V: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>,\n    S: <a class=\"trait\" href=\"hash32/trait.BuildHasher.html\" title=\"trait hash32::BuildHasher\">BuildHasher</a>,</div>"],["impl&lt;'a, T, S, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.Extend.html\" title=\"trait core::iter::traits::collect::Extend\">Extend</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.reference.html\">&amp;'a T</a>&gt; for <a class=\"struct\" href=\"heapless/struct.IndexSet.html\" title=\"struct heapless::IndexSet\">IndexSet</a>&lt;T, S, N&gt;<div class=\"where\">where\n    T: 'a + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"hash32/trait.Hash.html\" title=\"trait hash32::Hash\">Hash</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>,\n    S: <a class=\"trait\" href=\"hash32/trait.BuildHasher.html\" title=\"trait hash32::BuildHasher\">BuildHasher</a>,</div>"],["impl&lt;'a, T, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.Extend.html\" title=\"trait core::iter::traits::collect::Extend\">Extend</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.reference.html\">&amp;'a T</a>&gt; for <a class=\"struct\" href=\"heapless/struct.HistoryBuffer.html\" title=\"struct heapless::HistoryBuffer\">HistoryBuffer</a>&lt;T, N&gt;<div class=\"where\">where\n    T: 'a + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,</div>"],["impl&lt;'a, T, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.Extend.html\" title=\"trait core::iter::traits::collect::Extend\">Extend</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.reference.html\">&amp;'a T</a>&gt; for <a class=\"struct\" href=\"heapless/struct.Vec.html\" title=\"struct heapless::Vec\">Vec</a>&lt;T, N&gt;<div class=\"where\">where\n    T: 'a + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>,</div>"],["impl&lt;K, V, S, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.Extend.html\" title=\"trait core::iter::traits::collect::Extend\">Extend</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.tuple.html\">(K, V)</a>&gt; for <a class=\"struct\" href=\"heapless/struct.IndexMap.html\" title=\"struct heapless::IndexMap\">IndexMap</a>&lt;K, V, S, N&gt;<div class=\"where\">where\n    K: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"hash32/trait.Hash.html\" title=\"trait hash32::Hash\">Hash</a>,\n    S: <a class=\"trait\" href=\"hash32/trait.BuildHasher.html\" title=\"trait hash32::BuildHasher\">BuildHasher</a>,</div>"],["impl&lt;T, S, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.Extend.html\" title=\"trait core::iter::traits::collect::Extend\">Extend</a>&lt;T&gt; for <a class=\"struct\" href=\"heapless/struct.IndexSet.html\" title=\"struct heapless::IndexSet\">IndexSet</a>&lt;T, S, N&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"hash32/trait.Hash.html\" title=\"trait hash32::Hash\">Hash</a>,\n    S: <a class=\"trait\" href=\"hash32/trait.BuildHasher.html\" title=\"trait hash32::BuildHasher\">BuildHasher</a>,</div>"],["impl&lt;T, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.Extend.html\" title=\"trait core::iter::traits::collect::Extend\">Extend</a>&lt;T&gt; for <a class=\"struct\" href=\"heapless/struct.HistoryBuffer.html\" title=\"struct heapless::HistoryBuffer\">HistoryBuffer</a>&lt;T, N&gt;"],["impl&lt;T, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.Extend.html\" title=\"trait core::iter::traits::collect::Extend\">Extend</a>&lt;T&gt; for <a class=\"struct\" href=\"heapless/struct.Vec.html\" title=\"struct heapless::Vec\">Vec</a>&lt;T, N&gt;"]]],["proc_macro2",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.Extend.html\" title=\"trait core::iter::traits::collect::Extend\">Extend</a>&lt;<a class=\"enum\" href=\"proc_macro2/enum.TokenTree.html\" title=\"enum proc_macro2::TokenTree\">TokenTree</a>&gt; for <a class=\"struct\" href=\"proc_macro2/struct.TokenStream.html\" title=\"struct proc_macro2::TokenStream\">TokenStream</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.Extend.html\" title=\"trait core::iter::traits::collect::Extend\">Extend</a>&lt;<a class=\"struct\" href=\"proc_macro2/struct.TokenStream.html\" title=\"struct proc_macro2::TokenStream\">TokenStream</a>&gt; for <a class=\"struct\" href=\"proc_macro2/struct.TokenStream.html\" title=\"struct proc_macro2::TokenStream\">TokenStream</a>"]]],["trussed",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/iter/traits/collect/trait.Extend.html\" title=\"trait core::iter::traits::collect::Extend\">Extend</a>&lt;<a class=\"struct\" href=\"trussed/key/struct.Flags.html\" title=\"struct trussed::key::Flags\">Flags</a>&gt; for <a class=\"struct\" href=\"trussed/key/struct.Flags.html\" title=\"struct trussed::key::Flags\">Flags</a>"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[6402,872,413]}