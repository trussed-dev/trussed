(function() {
    var implementors = Object.fromEntries([["cosey",[["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"cosey/struct.EcdhEsHkdf256PublicKey.html\" title=\"struct cosey::EcdhEsHkdf256PublicKey\">EcdhEsHkdf256PublicKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"cosey/struct.Ed25519PublicKey.html\" title=\"struct cosey::Ed25519PublicKey\">Ed25519PublicKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"cosey/struct.P256PublicKey.html\" title=\"struct cosey::P256PublicKey\">P256PublicKey</a>"]]],["heapless",[["impl&lt;'de, K, V, S, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"heapless/struct.IndexMap.html\" title=\"struct heapless::IndexMap\">IndexMap</a>&lt;K, V, <a class=\"struct\" href=\"hash32/struct.BuildHasherDefault.html\" title=\"struct hash32::BuildHasherDefault\">BuildHasherDefault</a>&lt;S&gt;, N&gt;<div class=\"where\">where\n    K: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"hash32/trait.Hash.html\" title=\"trait hash32::Hash\">Hash</a> + <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,\n    V: <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,\n    S: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + <a class=\"trait\" href=\"hash32/trait.Hasher.html\" title=\"trait hash32::Hasher\">Hasher</a>,</div>"],["impl&lt;'de, K, V, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"heapless/struct.LinearMap.html\" title=\"struct heapless::LinearMap\">LinearMap</a>&lt;K, V, N&gt;<div class=\"where\">where\n    K: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,\n    V: <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,</div>"],["impl&lt;'de, T, KIND, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"heapless/binary_heap/struct.BinaryHeap.html\" title=\"struct heapless::binary_heap::BinaryHeap\">BinaryHeap</a>&lt;T, KIND, N&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.Ord.html\" title=\"trait core::cmp::Ord\">Ord</a> + <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,\n    KIND: <a class=\"trait\" href=\"heapless/binary_heap/trait.Kind.html\" title=\"trait heapless::binary_heap::Kind\">BinaryHeapKind</a>,</div>"],["impl&lt;'de, T, S, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"heapless/struct.IndexSet.html\" title=\"struct heapless::IndexSet\">IndexSet</a>&lt;T, <a class=\"struct\" href=\"hash32/struct.BuildHasherDefault.html\" title=\"struct hash32::BuildHasherDefault\">BuildHasherDefault</a>&lt;S&gt;, N&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"hash32/trait.Hash.html\" title=\"trait hash32::Hash\">Hash</a> + <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,\n    S: <a class=\"trait\" href=\"hash32/trait.Hasher.html\" title=\"trait hash32::Hasher\">Hasher</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,</div>"],["impl&lt;'de, T, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"heapless/struct.Vec.html\" title=\"struct heapless::Vec\">Vec</a>&lt;T, N&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,</div>"],["impl&lt;'de, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"heapless/struct.String.html\" title=\"struct heapless::String\">String</a>&lt;N&gt;"]]],["heapless_bytes",[["impl&lt;'de, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"heapless_bytes/struct.Bytes.html\" title=\"struct heapless_bytes::Bytes\">Bytes</a>&lt;N&gt;"]]],["littlefs2",[["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"littlefs2/fs/enum.FileType.html\" title=\"enum littlefs2::fs::FileType\">FileType</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"littlefs2/fs/struct.DirEntry.html\" title=\"struct littlefs2::fs::DirEntry\">DirEntry</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"littlefs2/fs/struct.Metadata.html\" title=\"struct littlefs2::fs::Metadata\">Metadata</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"littlefs2/path/struct.PathBuf.html\" title=\"struct littlefs2::path::PathBuf\">PathBuf</a>"]]],["serde",[]],["trussed",[["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"trussed/api/enum.NotBefore.html\" title=\"enum trussed::api::NotBefore\">NotBefore</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"trussed/key/enum.Kind.html\" title=\"enum trussed::key::Kind\">Kind</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"trussed/types/consent/enum.Error.html\" title=\"enum trussed::types::consent::Error\">Error</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"trussed/types/consent/enum.Level.html\" title=\"enum trussed::types::consent::Level\">Level</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"trussed/types/consent/enum.Urgency.html\" title=\"enum trussed::types::consent::Urgency\">Urgency</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"trussed/types/enum.KeySerialization.html\" title=\"enum trussed::types::KeySerialization\">KeySerialization</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"trussed/types/enum.Location.html\" title=\"enum trussed::types::Location\">Location</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"trussed/types/enum.Mechanism.html\" title=\"enum trussed::types::Mechanism\">Mechanism</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"trussed/types/enum.SignatureSerialization.html\" title=\"enum trussed::types::SignatureSerialization\">SignatureSerialization</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"trussed/types/reboot/enum.To.html\" title=\"enum trussed::types::reboot::To\">To</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"trussed/types/ui/enum.Status.html\" title=\"enum trussed::types::ui::Status\">Status</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Agree.html\" title=\"struct trussed::api::reply::Agree\">Agree</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Attest.html\" title=\"struct trussed::api::reply::Attest\">Attest</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Clear.html\" title=\"struct trussed::api::reply::Clear\">Clear</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.CreateCounter.html\" title=\"struct trussed::api::reply::CreateCounter\">CreateCounter</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.DebugDumpStore.html\" title=\"struct trussed::api::reply::DebugDumpStore\">DebugDumpStore</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Decrypt.html\" title=\"struct trussed::api::reply::Decrypt\">Decrypt</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Delete.html\" title=\"struct trussed::api::reply::Delete\">Delete</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.DeleteAllKeys.html\" title=\"struct trussed::api::reply::DeleteAllKeys\">DeleteAllKeys</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.DeleteCertificate.html\" title=\"struct trussed::api::reply::DeleteCertificate\">DeleteCertificate</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.DeriveKey.html\" title=\"struct trussed::api::reply::DeriveKey\">DeriveKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.DeserializeKey.html\" title=\"struct trussed::api::reply::DeserializeKey\">DeserializeKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Encrypt.html\" title=\"struct trussed::api::reply::Encrypt\">Encrypt</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Exists.html\" title=\"struct trussed::api::reply::Exists\">Exists</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.GenerateKey.html\" title=\"struct trussed::api::reply::GenerateKey\">GenerateKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.GenerateSecretKey.html\" title=\"struct trussed::api::reply::GenerateSecretKey\">GenerateSecretKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Hash.html\" title=\"struct trussed::api::reply::Hash\">Hash</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.IncrementCounter.html\" title=\"struct trussed::api::reply::IncrementCounter\">IncrementCounter</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.LocateFile.html\" title=\"struct trussed::api::reply::LocateFile\">LocateFile</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Metadata.html\" title=\"struct trussed::api::reply::Metadata\">Metadata</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.RandomBytes.html\" title=\"struct trussed::api::reply::RandomBytes\">RandomBytes</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.ReadCertificate.html\" title=\"struct trussed::api::reply::ReadCertificate\">ReadCertificate</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.ReadDirFilesFirst.html\" title=\"struct trussed::api::reply::ReadDirFilesFirst\">ReadDirFilesFirst</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.ReadDirFilesNext.html\" title=\"struct trussed::api::reply::ReadDirFilesNext\">ReadDirFilesNext</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.ReadDirFirst.html\" title=\"struct trussed::api::reply::ReadDirFirst\">ReadDirFirst</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.ReadDirNext.html\" title=\"struct trussed::api::reply::ReadDirNext\">ReadDirNext</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.ReadFile.html\" title=\"struct trussed::api::reply::ReadFile\">ReadFile</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Reboot.html\" title=\"struct trussed::api::reply::Reboot\">Reboot</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.RemoveDir.html\" title=\"struct trussed::api::reply::RemoveDir\">RemoveDir</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.RemoveDirAll.html\" title=\"struct trussed::api::reply::RemoveDirAll\">RemoveDirAll</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.RemoveFile.html\" title=\"struct trussed::api::reply::RemoveFile\">RemoveFile</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Rename.html\" title=\"struct trussed::api::reply::Rename\">Rename</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.RequestUserConsent.html\" title=\"struct trussed::api::reply::RequestUserConsent\">RequestUserConsent</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.SerdeExtension.html\" title=\"struct trussed::api::reply::SerdeExtension\">SerdeExtension</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.SerializeKey.html\" title=\"struct trussed::api::reply::SerializeKey\">SerializeKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.SetCustomStatus.html\" title=\"struct trussed::api::reply::SetCustomStatus\">SetCustomStatus</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Sign.html\" title=\"struct trussed::api::reply::Sign\">Sign</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.UnsafeInjectKey.html\" title=\"struct trussed::api::reply::UnsafeInjectKey\">UnsafeInjectKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.UnsafeInjectSharedKey.html\" title=\"struct trussed::api::reply::UnsafeInjectSharedKey\">UnsafeInjectSharedKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.UnwrapKey.html\" title=\"struct trussed::api::reply::UnwrapKey\">UnwrapKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Uptime.html\" title=\"struct trussed::api::reply::Uptime\">Uptime</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Verify.html\" title=\"struct trussed::api::reply::Verify\">Verify</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.Wink.html\" title=\"struct trussed::api::reply::Wink\">Wink</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.WrapKey.html\" title=\"struct trussed::api::reply::WrapKey\">WrapKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.WriteCertificate.html\" title=\"struct trussed::api::reply::WriteCertificate\">WriteCertificate</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/reply/struct.WriteFile.html\" title=\"struct trussed::api::reply::WriteFile\">WriteFile</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Agree.html\" title=\"struct trussed::api::request::Agree\">Agree</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Attest.html\" title=\"struct trussed::api::request::Attest\">Attest</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Clear.html\" title=\"struct trussed::api::request::Clear\">Clear</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.CreateCounter.html\" title=\"struct trussed::api::request::CreateCounter\">CreateCounter</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.DebugDumpStore.html\" title=\"struct trussed::api::request::DebugDumpStore\">DebugDumpStore</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Decrypt.html\" title=\"struct trussed::api::request::Decrypt\">Decrypt</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Delete.html\" title=\"struct trussed::api::request::Delete\">Delete</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.DeleteAllKeys.html\" title=\"struct trussed::api::request::DeleteAllKeys\">DeleteAllKeys</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.DeleteCertificate.html\" title=\"struct trussed::api::request::DeleteCertificate\">DeleteCertificate</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.DeriveKey.html\" title=\"struct trussed::api::request::DeriveKey\">DeriveKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.DeserializeKey.html\" title=\"struct trussed::api::request::DeserializeKey\">DeserializeKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Encrypt.html\" title=\"struct trussed::api::request::Encrypt\">Encrypt</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Exists.html\" title=\"struct trussed::api::request::Exists\">Exists</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.GenerateKey.html\" title=\"struct trussed::api::request::GenerateKey\">GenerateKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.GenerateSecretKey.html\" title=\"struct trussed::api::request::GenerateSecretKey\">GenerateSecretKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Hash.html\" title=\"struct trussed::api::request::Hash\">Hash</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.IncrementCounter.html\" title=\"struct trussed::api::request::IncrementCounter\">IncrementCounter</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.LocateFile.html\" title=\"struct trussed::api::request::LocateFile\">LocateFile</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Metadata.html\" title=\"struct trussed::api::request::Metadata\">Metadata</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.RandomBytes.html\" title=\"struct trussed::api::request::RandomBytes\">RandomBytes</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.ReadCertificate.html\" title=\"struct trussed::api::request::ReadCertificate\">ReadCertificate</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.ReadDirFilesFirst.html\" title=\"struct trussed::api::request::ReadDirFilesFirst\">ReadDirFilesFirst</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.ReadDirFilesNext.html\" title=\"struct trussed::api::request::ReadDirFilesNext\">ReadDirFilesNext</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.ReadDirFirst.html\" title=\"struct trussed::api::request::ReadDirFirst\">ReadDirFirst</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.ReadDirNext.html\" title=\"struct trussed::api::request::ReadDirNext\">ReadDirNext</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.ReadFile.html\" title=\"struct trussed::api::request::ReadFile\">ReadFile</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Reboot.html\" title=\"struct trussed::api::request::Reboot\">Reboot</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.RemoveDir.html\" title=\"struct trussed::api::request::RemoveDir\">RemoveDir</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.RemoveDirAll.html\" title=\"struct trussed::api::request::RemoveDirAll\">RemoveDirAll</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.RemoveFile.html\" title=\"struct trussed::api::request::RemoveFile\">RemoveFile</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Rename.html\" title=\"struct trussed::api::request::Rename\">Rename</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.RequestUserConsent.html\" title=\"struct trussed::api::request::RequestUserConsent\">RequestUserConsent</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.SerdeExtension.html\" title=\"struct trussed::api::request::SerdeExtension\">SerdeExtension</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.SerializeKey.html\" title=\"struct trussed::api::request::SerializeKey\">SerializeKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.SetCustomStatus.html\" title=\"struct trussed::api::request::SetCustomStatus\">SetCustomStatus</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Sign.html\" title=\"struct trussed::api::request::Sign\">Sign</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.UnsafeInjectKey.html\" title=\"struct trussed::api::request::UnsafeInjectKey\">UnsafeInjectKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.UnsafeInjectSharedKey.html\" title=\"struct trussed::api::request::UnsafeInjectSharedKey\">UnsafeInjectSharedKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.UnwrapKey.html\" title=\"struct trussed::api::request::UnwrapKey\">UnwrapKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Uptime.html\" title=\"struct trussed::api::request::Uptime\">Uptime</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Verify.html\" title=\"struct trussed::api::request::Verify\">Verify</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.Wink.html\" title=\"struct trussed::api::request::Wink\">Wink</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.WrapKey.html\" title=\"struct trussed::api::request::WrapKey\">WrapKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.WriteCertificate.html\" title=\"struct trussed::api::request::WriteCertificate\">WriteCertificate</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/api/request/struct.WriteFile.html\" title=\"struct trussed::api::request::WriteFile\">WriteFile</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/key/struct.Flags.html\" title=\"struct trussed::key::Flags\">Flags</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/types/struct.CertId.html\" title=\"struct trussed::types::CertId\">CertId</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/types/struct.CounterId.html\" title=\"struct trussed::types::CounterId\">CounterId</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/types/struct.Id.html\" title=\"struct trussed::types::Id\">Id</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/types/struct.KeyId.html\" title=\"struct trussed::types::KeyId\">KeyId</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"trussed/types/struct.StorageAttributes.html\" title=\"struct trussed::types::StorageAttributes\">StorageAttributes</a>"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[848,5066,402,1079,13,30487]}