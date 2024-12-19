(function() {
    var implementors = Object.fromEntries([["cosey",[["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"cosey/enum.PublicKey.html\" title=\"enum cosey::PublicKey\">PublicKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"cosey/struct.EcdhEsHkdf256PublicKey.html\" title=\"struct cosey::EcdhEsHkdf256PublicKey\">EcdhEsHkdf256PublicKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"cosey/struct.Ed25519PublicKey.html\" title=\"struct cosey::Ed25519PublicKey\">Ed25519PublicKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"cosey/struct.P256PublicKey.html\" title=\"struct cosey::P256PublicKey\">P256PublicKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"cosey/struct.TotpPublicKey.html\" title=\"struct cosey::TotpPublicKey\">TotpPublicKey</a>"]]],["heapless",[["impl&lt;K, V, S, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless/struct.IndexMap.html\" title=\"struct heapless::IndexMap\">IndexMap</a>&lt;K, V, S, N&gt;<div class=\"where\">where\n    K: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"hash32/trait.Hash.html\" title=\"trait hash32::Hash\">Hash</a> + <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,\n    S: <a class=\"trait\" href=\"hash32/trait.BuildHasher.html\" title=\"trait hash32::BuildHasher\">BuildHasher</a>,\n    V: <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl&lt;K, V, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless/struct.LinearMap.html\" title=\"struct heapless::LinearMap\">LinearMap</a>&lt;K, V, N&gt;<div class=\"where\">where\n    K: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,\n    V: <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl&lt;T, KIND, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless/binary_heap/struct.BinaryHeap.html\" title=\"struct heapless::binary_heap::BinaryHeap\">BinaryHeap</a>&lt;T, KIND, N&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/cmp/trait.Ord.html\" title=\"trait core::cmp::Ord\">Ord</a> + <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,\n    KIND: <a class=\"trait\" href=\"heapless/binary_heap/trait.Kind.html\" title=\"trait heapless::binary_heap::Kind\">BinaryHeapKind</a>,</div>"],["impl&lt;T, S, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless/struct.IndexSet.html\" title=\"struct heapless::IndexSet\">IndexSet</a>&lt;T, S, N&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"hash32/trait.Hash.html\" title=\"trait hash32::Hash\">Hash</a> + <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,\n    S: <a class=\"trait\" href=\"hash32/trait.BuildHasher.html\" title=\"trait hash32::BuildHasher\">BuildHasher</a>,</div>"],["impl&lt;T, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless/struct.Vec.html\" title=\"struct heapless::Vec\">Vec</a>&lt;T, N&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless/struct.String.html\" title=\"struct heapless::String\">String</a>&lt;N&gt;"]]],["heapless_bytes",[["impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless_bytes/struct.Bytes.html\" title=\"struct heapless_bytes::Bytes\">Bytes</a>&lt;N&gt;"]]],["littlefs2_core",[["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"littlefs2_core/enum.FileType.html\" title=\"enum littlefs2_core::FileType\">FileType</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"littlefs2_core/struct.DirEntry.html\" title=\"struct littlefs2_core::DirEntry\">DirEntry</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"littlefs2_core/struct.Metadata.html\" title=\"struct littlefs2_core::Metadata\">Metadata</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"littlefs2_core/struct.PathBuf.html\" title=\"struct littlefs2_core::PathBuf\">PathBuf</a>"]]],["serde",[]],["trussed",[["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed/key/enum.Kind.html\" title=\"enum trussed::key::Kind\">Kind</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed/types/consent/enum.Urgency.html\" title=\"enum trussed::types::consent::Urgency\">Urgency</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed/types/ui/enum.Status.html\" title=\"enum trussed::types::ui::Status\">Status</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed/key/struct.Flags.html\" title=\"struct trussed::key::Flags\">Flags</a>"]]],["trussed_core",[["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed_core/types/enum.Location.html\" title=\"enum trussed_core::types::Location\">Location</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed_core/types/enum.Mechanism.html\" title=\"enum trussed_core::types::Mechanism\">Mechanism</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed_core/types/enum.NotBefore.html\" title=\"enum trussed_core::types::NotBefore\">NotBefore</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/types/struct.CertId.html\" title=\"struct trussed_core::types::CertId\">CertId</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/types/struct.CounterId.html\" title=\"struct trussed_core::types::CounterId\">CounterId</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/types/struct.EncryptedData.html\" title=\"struct trussed_core::types::EncryptedData\">EncryptedData</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/types/struct.Id.html\" title=\"struct trussed_core::types::Id\">Id</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/types/struct.KeyId.html\" title=\"struct trussed_core::types::KeyId\">KeyId</a>"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[1234,4297,382,988,13,954,2016]}