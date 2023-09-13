(function() {var implementors = {
"bitflags":[["impl&lt;B: <a class=\"trait\" href=\"bitflags/trait.Flags.html\" title=\"trait bitflags::Flags\">Flags</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"bitflags/iter/struct.IterNames.html\" title=\"struct bitflags::iter::IterNames\">IterNames</a>&lt;B&gt;"],["impl&lt;B: <a class=\"trait\" href=\"bitflags/trait.Flags.html\" title=\"trait bitflags::Flags\">Flags</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"bitflags/iter/struct.Iter.html\" title=\"struct bitflags::iter::Iter\">Iter</a>&lt;B&gt;"]],
"der":[["impl&lt;'a, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"der/asn1/struct.SetOfRefIter.html\" title=\"struct der::asn1::SetOfRefIter\">SetOfRefIter</a>&lt;'a, T&gt;<span class=\"where fmt-newline\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"der/trait.Decodable.html\" title=\"trait der::Decodable\">Decodable</a>&lt;'a&gt; + <a class=\"trait\" href=\"der/trait.Encodable.html\" title=\"trait der::Encodable\">Encodable</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/cmp/trait.Ord.html\" title=\"trait core::cmp::Ord\">Ord</a>,</span>"],["impl&lt;'a, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"der/asn1/struct.SequenceIter.html\" title=\"struct der::asn1::SequenceIter\">SequenceIter</a>&lt;'a, T&gt;<span class=\"where fmt-newline\">where\n    T: <a class=\"trait\" href=\"der/trait.Decodable.html\" title=\"trait der::Decodable\">Decodable</a>&lt;'a&gt;,</span>"]],
"generic_array":[["impl&lt;T, N&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"generic_array/iter/struct.GenericArrayIter.html\" title=\"struct generic_array::iter::GenericArrayIter\">GenericArrayIter</a>&lt;T, N&gt;<span class=\"where fmt-newline\">where\n    N: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;T&gt;,</span>"]],
"heapless":[["impl&lt;'a, T, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.72.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"heapless/struct.OldestOrdered.html\" title=\"struct heapless::OldestOrdered\">OldestOrdered</a>&lt;'a, T, N&gt;"],["impl&lt;'a, T, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.72.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"heapless/spsc/struct.Iter.html\" title=\"struct heapless::spsc::Iter\">Iter</a>&lt;'a, T, N&gt;"],["impl&lt;'a, T, Idx, K, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.72.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"heapless/sorted_linked_list/struct.Iter.html\" title=\"struct heapless::sorted_linked_list::Iter\">Iter</a>&lt;'a, T, Idx, K, N&gt;<span class=\"where fmt-newline\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/cmp/trait.Ord.html\" title=\"trait core::cmp::Ord\">Ord</a>,\n    Idx: <a class=\"trait\" href=\"heapless/sorted_linked_list/trait.SortedLinkedListIndex.html\" title=\"trait heapless::sorted_linked_list::SortedLinkedListIndex\">SortedLinkedListIndex</a>,\n    K: <a class=\"trait\" href=\"heapless/sorted_linked_list/trait.Kind.html\" title=\"trait heapless::sorted_linked_list::Kind\">Kind</a>,</span>"],["impl&lt;'a, T, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.72.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"heapless/spsc/struct.IterMut.html\" title=\"struct heapless::spsc::IterMut\">IterMut</a>&lt;'a, T, N&gt;"]],
"inout":[["impl&lt;'inp, 'out, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"inout/struct.InOutBufIter.html\" title=\"struct inout::InOutBufIter\">InOutBufIter</a>&lt;'inp, 'out, T&gt;"]],
"littlefs2":[["impl&lt;'a, 'b, S: <a class=\"trait\" href=\"littlefs2/driver/trait.Storage.html\" title=\"trait littlefs2::driver::Storage\">Storage</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"littlefs2/fs/struct.ReadDir.html\" title=\"struct littlefs2::fs::ReadDir\">ReadDir</a>&lt;'a, 'b, S&gt;"]],
"memchr":[["impl&lt;'h&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/struct.Memchr3.html\" title=\"struct memchr::Memchr3\">Memchr3</a>&lt;'h&gt;"],["impl&lt;'a, 'h&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/arch/x86_64/avx2/memchr/struct.ThreeIter.html\" title=\"struct memchr::arch::x86_64::avx2::memchr::ThreeIter\">ThreeIter</a>&lt;'a, 'h&gt;"],["impl&lt;'h, 'n&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/memmem/struct.FindIter.html\" title=\"struct memchr::memmem::FindIter\">FindIter</a>&lt;'h, 'n&gt;"],["impl&lt;'a, 'h&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/arch/all/memchr/struct.OneIter.html\" title=\"struct memchr::arch::all::memchr::OneIter\">OneIter</a>&lt;'a, 'h&gt;"],["impl&lt;'a, 'h&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/arch/all/memchr/struct.TwoIter.html\" title=\"struct memchr::arch::all::memchr::TwoIter\">TwoIter</a>&lt;'a, 'h&gt;"],["impl&lt;'h, 'n&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/memmem/struct.FindRevIter.html\" title=\"struct memchr::memmem::FindRevIter\">FindRevIter</a>&lt;'h, 'n&gt;"],["impl&lt;'h&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/struct.Memchr.html\" title=\"struct memchr::Memchr\">Memchr</a>&lt;'h&gt;"],["impl&lt;'a, 'h&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/arch/all/memchr/struct.ThreeIter.html\" title=\"struct memchr::arch::all::memchr::ThreeIter\">ThreeIter</a>&lt;'a, 'h&gt;"],["impl&lt;'h&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/struct.Memchr2.html\" title=\"struct memchr::Memchr2\">Memchr2</a>&lt;'h&gt;"],["impl&lt;'a, 'h&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/arch/x86_64/sse2/memchr/struct.OneIter.html\" title=\"struct memchr::arch::x86_64::sse2::memchr::OneIter\">OneIter</a>&lt;'a, 'h&gt;"],["impl&lt;'a, 'h&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/arch/x86_64/sse2/memchr/struct.TwoIter.html\" title=\"struct memchr::arch::x86_64::sse2::memchr::TwoIter\">TwoIter</a>&lt;'a, 'h&gt;"],["impl&lt;'a, 'h&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/arch/x86_64/avx2/memchr/struct.TwoIter.html\" title=\"struct memchr::arch::x86_64::avx2::memchr::TwoIter\">TwoIter</a>&lt;'a, 'h&gt;"],["impl&lt;'a, 'h&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/arch/x86_64/sse2/memchr/struct.ThreeIter.html\" title=\"struct memchr::arch::x86_64::sse2::memchr::ThreeIter\">ThreeIter</a>&lt;'a, 'h&gt;"],["impl&lt;'a, 'h&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"memchr/arch/x86_64/avx2/memchr/struct.OneIter.html\" title=\"struct memchr::arch::x86_64::avx2::memchr::OneIter\">OneIter</a>&lt;'a, 'h&gt;"]],
"proc_macro2":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"proc_macro2/token_stream/struct.IntoIter.html\" title=\"struct proc_macro2::token_stream::IntoIter\">IntoIter</a>"]],
"serde_cbor":[["impl&lt;'de, R, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.72.0/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a> for <a class=\"struct\" href=\"serde_cbor/struct.StreamDeserializer.html\" title=\"struct serde_cbor::StreamDeserializer\">StreamDeserializer</a>&lt;'de, R, T&gt;<span class=\"where fmt-newline\">where\n    R: <a class=\"trait\" href=\"serde_cbor/de/trait.Read.html\" title=\"trait serde_cbor::de::Read\">Read</a>&lt;'de&gt;,\n    T: <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,</span>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()