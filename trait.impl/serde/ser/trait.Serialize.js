(function() {
    var implementors = Object.fromEntries([["cosey",[["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"cosey/enum.PublicKey.html\" title=\"enum cosey::PublicKey\">PublicKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"cosey/struct.EcdhEsHkdf256PublicKey.html\" title=\"struct cosey::EcdhEsHkdf256PublicKey\">EcdhEsHkdf256PublicKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"cosey/struct.Ed25519PublicKey.html\" title=\"struct cosey::Ed25519PublicKey\">Ed25519PublicKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"cosey/struct.P256PublicKey.html\" title=\"struct cosey::P256PublicKey\">P256PublicKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"cosey/struct.TotpPublicKey.html\" title=\"struct cosey::TotpPublicKey\">TotpPublicKey</a>"]]],["heapless",[["impl&lt;K, V, S, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless/struct.IndexMap.html\" title=\"struct heapless::IndexMap\">IndexMap</a>&lt;K, V, S, N&gt;<div class=\"where\">where\n    K: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"hash32/trait.Hash.html\" title=\"trait hash32::Hash\">Hash</a> + <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,\n    S: <a class=\"trait\" href=\"hash32/trait.BuildHasher.html\" title=\"trait hash32::BuildHasher\">BuildHasher</a>,\n    V: <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl&lt;K, V, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless/struct.LinearMap.html\" title=\"struct heapless::LinearMap\">LinearMap</a>&lt;K, V, N&gt;<div class=\"where\">where\n    K: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,\n    V: <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl&lt;T, KIND, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless/binary_heap/struct.BinaryHeap.html\" title=\"struct heapless::binary_heap::BinaryHeap\">BinaryHeap</a>&lt;T, KIND, N&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/cmp/trait.Ord.html\" title=\"trait core::cmp::Ord\">Ord</a> + <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,\n    KIND: <a class=\"trait\" href=\"heapless/binary_heap/trait.Kind.html\" title=\"trait heapless::binary_heap::Kind\">BinaryHeapKind</a>,</div>"],["impl&lt;T, S, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless/struct.IndexSet.html\" title=\"struct heapless::IndexSet\">IndexSet</a>&lt;T, S, N&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"hash32/trait.Hash.html\" title=\"trait hash32::Hash\">Hash</a> + <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,\n    S: <a class=\"trait\" href=\"hash32/trait.BuildHasher.html\" title=\"trait hash32::BuildHasher\">BuildHasher</a>,</div>"],["impl&lt;T, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless/struct.Vec.html\" title=\"struct heapless::Vec\">Vec</a>&lt;T, N&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless/struct.String.html\" title=\"struct heapless::String\">String</a>&lt;N&gt;"]]],["heapless_bytes",[["impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"heapless_bytes/struct.Bytes.html\" title=\"struct heapless_bytes::Bytes\">Bytes</a>&lt;N&gt;"]]],["littlefs2_core",[["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"littlefs2_core/enum.FileType.html\" title=\"enum littlefs2_core::FileType\">FileType</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"littlefs2_core/struct.DirEntry.html\" title=\"struct littlefs2_core::DirEntry\">DirEntry</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"littlefs2_core/struct.Metadata.html\" title=\"struct littlefs2_core::Metadata\">Metadata</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"littlefs2_core/struct.PathBuf.html\" title=\"struct littlefs2_core::PathBuf\">PathBuf</a>"]]],["serde",[]],["trussed",[["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed/key/enum.Kind.html\" title=\"enum trussed::key::Kind\">Kind</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed/types/consent/enum.Urgency.html\" title=\"enum trussed::types::consent::Urgency\">Urgency</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed/types/ui/enum.Status.html\" title=\"enum trussed::types::ui::Status\">Status</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed/key/struct.Flags.html\" title=\"struct trussed::key::Flags\">Flags</a>"]]],["trussed_core",[["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed_core/api/enum.NotBefore.html\" title=\"enum trussed_core::api::NotBefore\">NotBefore</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed_core/types/consent/enum.Error.html\" title=\"enum trussed_core::types::consent::Error\">Error</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed_core/types/consent/enum.Level.html\" title=\"enum trussed_core::types::consent::Level\">Level</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed_core/types/enum.KeySerialization.html\" title=\"enum trussed_core::types::KeySerialization\">KeySerialization</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed_core/types/enum.Location.html\" title=\"enum trussed_core::types::Location\">Location</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed_core/types/enum.Mechanism.html\" title=\"enum trussed_core::types::Mechanism\">Mechanism</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed_core/types/enum.SignatureSerialization.html\" title=\"enum trussed_core::types::SignatureSerialization\">SignatureSerialization</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"trussed_core/types/reboot/enum.To.html\" title=\"enum trussed_core::types::reboot::To\">To</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Agree.html\" title=\"struct trussed_core::api::reply::Agree\">Agree</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Attest.html\" title=\"struct trussed_core::api::reply::Attest\">Attest</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Clear.html\" title=\"struct trussed_core::api::reply::Clear\">Clear</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.CreateCounter.html\" title=\"struct trussed_core::api::reply::CreateCounter\">CreateCounter</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.DebugDumpStore.html\" title=\"struct trussed_core::api::reply::DebugDumpStore\">DebugDumpStore</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Decrypt.html\" title=\"struct trussed_core::api::reply::Decrypt\">Decrypt</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Delete.html\" title=\"struct trussed_core::api::reply::Delete\">Delete</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.DeleteAllKeys.html\" title=\"struct trussed_core::api::reply::DeleteAllKeys\">DeleteAllKeys</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.DeleteCertificate.html\" title=\"struct trussed_core::api::reply::DeleteCertificate\">DeleteCertificate</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.DeriveKey.html\" title=\"struct trussed_core::api::reply::DeriveKey\">DeriveKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.DeserializeKey.html\" title=\"struct trussed_core::api::reply::DeserializeKey\">DeserializeKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Encrypt.html\" title=\"struct trussed_core::api::reply::Encrypt\">Encrypt</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Exists.html\" title=\"struct trussed_core::api::reply::Exists\">Exists</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.GenerateKey.html\" title=\"struct trussed_core::api::reply::GenerateKey\">GenerateKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.GenerateSecretKey.html\" title=\"struct trussed_core::api::reply::GenerateSecretKey\">GenerateSecretKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Hash.html\" title=\"struct trussed_core::api::reply::Hash\">Hash</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.IncrementCounter.html\" title=\"struct trussed_core::api::reply::IncrementCounter\">IncrementCounter</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.LocateFile.html\" title=\"struct trussed_core::api::reply::LocateFile\">LocateFile</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Metadata.html\" title=\"struct trussed_core::api::reply::Metadata\">Metadata</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.RandomBytes.html\" title=\"struct trussed_core::api::reply::RandomBytes\">RandomBytes</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.ReadCertificate.html\" title=\"struct trussed_core::api::reply::ReadCertificate\">ReadCertificate</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.ReadDirFilesFirst.html\" title=\"struct trussed_core::api::reply::ReadDirFilesFirst\">ReadDirFilesFirst</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.ReadDirFilesNext.html\" title=\"struct trussed_core::api::reply::ReadDirFilesNext\">ReadDirFilesNext</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.ReadDirFirst.html\" title=\"struct trussed_core::api::reply::ReadDirFirst\">ReadDirFirst</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.ReadDirNext.html\" title=\"struct trussed_core::api::reply::ReadDirNext\">ReadDirNext</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.ReadFile.html\" title=\"struct trussed_core::api::reply::ReadFile\">ReadFile</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Reboot.html\" title=\"struct trussed_core::api::reply::Reboot\">Reboot</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.RemoveDir.html\" title=\"struct trussed_core::api::reply::RemoveDir\">RemoveDir</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.RemoveDirAll.html\" title=\"struct trussed_core::api::reply::RemoveDirAll\">RemoveDirAll</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.RemoveFile.html\" title=\"struct trussed_core::api::reply::RemoveFile\">RemoveFile</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Rename.html\" title=\"struct trussed_core::api::reply::Rename\">Rename</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.RequestUserConsent.html\" title=\"struct trussed_core::api::reply::RequestUserConsent\">RequestUserConsent</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.SerdeExtension.html\" title=\"struct trussed_core::api::reply::SerdeExtension\">SerdeExtension</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.SerializeKey.html\" title=\"struct trussed_core::api::reply::SerializeKey\">SerializeKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.SetCustomStatus.html\" title=\"struct trussed_core::api::reply::SetCustomStatus\">SetCustomStatus</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Sign.html\" title=\"struct trussed_core::api::reply::Sign\">Sign</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.UnsafeInjectKey.html\" title=\"struct trussed_core::api::reply::UnsafeInjectKey\">UnsafeInjectKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.UnsafeInjectSharedKey.html\" title=\"struct trussed_core::api::reply::UnsafeInjectSharedKey\">UnsafeInjectSharedKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.UnwrapKey.html\" title=\"struct trussed_core::api::reply::UnwrapKey\">UnwrapKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Uptime.html\" title=\"struct trussed_core::api::reply::Uptime\">Uptime</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Verify.html\" title=\"struct trussed_core::api::reply::Verify\">Verify</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.Wink.html\" title=\"struct trussed_core::api::reply::Wink\">Wink</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.WrapKey.html\" title=\"struct trussed_core::api::reply::WrapKey\">WrapKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.WriteCertificate.html\" title=\"struct trussed_core::api::reply::WriteCertificate\">WriteCertificate</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/reply/struct.WriteFile.html\" title=\"struct trussed_core::api::reply::WriteFile\">WriteFile</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Agree.html\" title=\"struct trussed_core::api::request::Agree\">Agree</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Attest.html\" title=\"struct trussed_core::api::request::Attest\">Attest</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Clear.html\" title=\"struct trussed_core::api::request::Clear\">Clear</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.CreateCounter.html\" title=\"struct trussed_core::api::request::CreateCounter\">CreateCounter</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.DebugDumpStore.html\" title=\"struct trussed_core::api::request::DebugDumpStore\">DebugDumpStore</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Decrypt.html\" title=\"struct trussed_core::api::request::Decrypt\">Decrypt</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Delete.html\" title=\"struct trussed_core::api::request::Delete\">Delete</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.DeleteAllKeys.html\" title=\"struct trussed_core::api::request::DeleteAllKeys\">DeleteAllKeys</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.DeleteCertificate.html\" title=\"struct trussed_core::api::request::DeleteCertificate\">DeleteCertificate</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.DeriveKey.html\" title=\"struct trussed_core::api::request::DeriveKey\">DeriveKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.DeserializeKey.html\" title=\"struct trussed_core::api::request::DeserializeKey\">DeserializeKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Encrypt.html\" title=\"struct trussed_core::api::request::Encrypt\">Encrypt</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Exists.html\" title=\"struct trussed_core::api::request::Exists\">Exists</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.GenerateKey.html\" title=\"struct trussed_core::api::request::GenerateKey\">GenerateKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.GenerateSecretKey.html\" title=\"struct trussed_core::api::request::GenerateSecretKey\">GenerateSecretKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Hash.html\" title=\"struct trussed_core::api::request::Hash\">Hash</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.IncrementCounter.html\" title=\"struct trussed_core::api::request::IncrementCounter\">IncrementCounter</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.LocateFile.html\" title=\"struct trussed_core::api::request::LocateFile\">LocateFile</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Metadata.html\" title=\"struct trussed_core::api::request::Metadata\">Metadata</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.RandomBytes.html\" title=\"struct trussed_core::api::request::RandomBytes\">RandomBytes</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.ReadCertificate.html\" title=\"struct trussed_core::api::request::ReadCertificate\">ReadCertificate</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.ReadDirFilesFirst.html\" title=\"struct trussed_core::api::request::ReadDirFilesFirst\">ReadDirFilesFirst</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.ReadDirFilesNext.html\" title=\"struct trussed_core::api::request::ReadDirFilesNext\">ReadDirFilesNext</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.ReadDirFirst.html\" title=\"struct trussed_core::api::request::ReadDirFirst\">ReadDirFirst</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.ReadDirNext.html\" title=\"struct trussed_core::api::request::ReadDirNext\">ReadDirNext</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.ReadFile.html\" title=\"struct trussed_core::api::request::ReadFile\">ReadFile</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Reboot.html\" title=\"struct trussed_core::api::request::Reboot\">Reboot</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.RemoveDir.html\" title=\"struct trussed_core::api::request::RemoveDir\">RemoveDir</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.RemoveDirAll.html\" title=\"struct trussed_core::api::request::RemoveDirAll\">RemoveDirAll</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.RemoveFile.html\" title=\"struct trussed_core::api::request::RemoveFile\">RemoveFile</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Rename.html\" title=\"struct trussed_core::api::request::Rename\">Rename</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.RequestUserConsent.html\" title=\"struct trussed_core::api::request::RequestUserConsent\">RequestUserConsent</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.SerdeExtension.html\" title=\"struct trussed_core::api::request::SerdeExtension\">SerdeExtension</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.SerializeKey.html\" title=\"struct trussed_core::api::request::SerializeKey\">SerializeKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.SetCustomStatus.html\" title=\"struct trussed_core::api::request::SetCustomStatus\">SetCustomStatus</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Sign.html\" title=\"struct trussed_core::api::request::Sign\">Sign</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.UnsafeInjectKey.html\" title=\"struct trussed_core::api::request::UnsafeInjectKey\">UnsafeInjectKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.UnsafeInjectSharedKey.html\" title=\"struct trussed_core::api::request::UnsafeInjectSharedKey\">UnsafeInjectSharedKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.UnwrapKey.html\" title=\"struct trussed_core::api::request::UnwrapKey\">UnwrapKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Uptime.html\" title=\"struct trussed_core::api::request::Uptime\">Uptime</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Verify.html\" title=\"struct trussed_core::api::request::Verify\">Verify</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.Wink.html\" title=\"struct trussed_core::api::request::Wink\">Wink</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.WrapKey.html\" title=\"struct trussed_core::api::request::WrapKey\">WrapKey</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.WriteCertificate.html\" title=\"struct trussed_core::api::request::WriteCertificate\">WriteCertificate</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/api/request/struct.WriteFile.html\" title=\"struct trussed_core::api::request::WriteFile\">WriteFile</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/types/struct.CertId.html\" title=\"struct trussed_core::types::CertId\">CertId</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/types/struct.CounterId.html\" title=\"struct trussed_core::types::CounterId\">CounterId</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/types/struct.Id.html\" title=\"struct trussed_core::types::Id\">Id</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/types/struct.KeyId.html\" title=\"struct trussed_core::types::KeyId\">KeyId</a>"],["impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"trussed_core/types/struct.StorageAttributes.html\" title=\"struct trussed_core::types::StorageAttributes\">StorageAttributes</a>"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[1234,4297,382,988,13,954,27800]}