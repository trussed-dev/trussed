(function() {var implementors = {
"aes":[["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"aes/struct.Aes128.html\" title=\"struct aes::Aes128\">Aes128</a>"],["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"aes/struct.Aes128Dec.html\" title=\"struct aes::Aes128Dec\">Aes128Dec</a>"],["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"aes/struct.Aes128Enc.html\" title=\"struct aes::Aes128Enc\">Aes128Enc</a>"],["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"aes/struct.Aes192.html\" title=\"struct aes::Aes192\">Aes192</a>"],["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"aes/struct.Aes192Dec.html\" title=\"struct aes::Aes192Dec\">Aes192Dec</a>"],["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"aes/struct.Aes192Enc.html\" title=\"struct aes::Aes192Enc\">Aes192Enc</a>"],["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"aes/struct.Aes256.html\" title=\"struct aes::Aes256\">Aes256</a>"],["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"aes/struct.Aes256Dec.html\" title=\"struct aes::Aes256Dec\">Aes256Dec</a>"],["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"aes/struct.Aes256Enc.html\" title=\"struct aes::Aes256Enc\">Aes256Enc</a>"]],
"cbc":[["impl&lt;C&gt; <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"cbc/struct.Decryptor.html\" title=\"struct cbc::Decryptor\">Decryptor</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"cipher/block/trait.BlockDecryptMut.html\" title=\"trait cipher::block::BlockDecryptMut\">BlockDecryptMut</a> + <a class=\"trait\" href=\"cipher/block/trait.BlockCipher.html\" title=\"trait cipher::block::BlockCipher\">BlockCipher</a> + <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a>,</div>"],["impl&lt;C&gt; <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"cbc/struct.Encryptor.html\" title=\"struct cbc::Encryptor\">Encryptor</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"cipher/block/trait.BlockEncryptMut.html\" title=\"trait cipher::block::BlockEncryptMut\">BlockEncryptMut</a> + <a class=\"trait\" href=\"cipher/block/trait.BlockCipher.html\" title=\"trait cipher::block::BlockCipher\">BlockCipher</a> + <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a>,</div>"]],
"des":[["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"des/struct.Des.html\" title=\"struct des::Des\">Des</a>"],["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"des/struct.TdesEde2.html\" title=\"struct des::TdesEde2\">TdesEde2</a>"],["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"des/struct.TdesEde3.html\" title=\"struct des::TdesEde3\">TdesEde3</a>"],["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"des/struct.TdesEee2.html\" title=\"struct des::TdesEee2\">TdesEee2</a>"],["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"des/struct.TdesEee3.html\" title=\"struct des::TdesEee3\">TdesEee3</a>"]],
"digest":[["impl&lt;T, OutSize, O&gt; <a class=\"trait\" href=\"digest/core_api/trait.AlgorithmName.html\" title=\"trait digest::core_api::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"digest/core_api/struct.CtVariableCoreWrapper.html\" title=\"struct digest::core_api::CtVariableCoreWrapper\">CtVariableCoreWrapper</a>&lt;T, OutSize, O&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"digest/core_api/trait.VariableOutputCore.html\" title=\"trait digest::core_api::VariableOutputCore\">VariableOutputCore</a> + <a class=\"trait\" href=\"digest/core_api/trait.AlgorithmName.html\" title=\"trait digest::core_api::AlgorithmName\">AlgorithmName</a>,\n    OutSize: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.80.1/core/primitive.u8.html\">u8</a>&gt; + <a class=\"trait\" href=\"typenum/type_operators/trait.IsLessOrEqual.html\" title=\"trait typenum::type_operators::IsLessOrEqual\">IsLessOrEqual</a>&lt;T::<a class=\"associatedtype\" href=\"digest/trait.OutputSizeUser.html#associatedtype.OutputSize\" title=\"type digest::OutputSizeUser::OutputSize\">OutputSize</a>&gt;,\n    <a class=\"type\" href=\"typenum/operator_aliases/type.LeEq.html\" title=\"type typenum::operator_aliases::LeEq\">LeEq</a>&lt;OutSize, T::<a class=\"associatedtype\" href=\"digest/trait.OutputSizeUser.html#associatedtype.OutputSize\" title=\"type digest::OutputSizeUser::OutputSize\">OutputSize</a>&gt;: <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,\n    T::<a class=\"associatedtype\" href=\"digest/core_api/trait.BlockSizeUser.html#associatedtype.BlockSize\" title=\"type digest::core_api::BlockSizeUser::BlockSize\">BlockSize</a>: <a class=\"trait\" href=\"typenum/type_operators/trait.IsLess.html\" title=\"trait typenum::type_operators::IsLess\">IsLess</a>&lt;<a class=\"type\" href=\"digest/consts/type.U256.html\" title=\"type digest::consts::U256\">U256</a>&gt;,\n    <a class=\"type\" href=\"typenum/operator_aliases/type.Le.html\" title=\"type typenum::operator_aliases::Le\">Le</a>&lt;T::<a class=\"associatedtype\" href=\"digest/core_api/trait.BlockSizeUser.html#associatedtype.BlockSize\" title=\"type digest::core_api::BlockSizeUser::BlockSize\">BlockSize</a>, <a class=\"type\" href=\"digest/consts/type.U256.html\" title=\"type digest::consts::U256\">U256</a>&gt;: <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,</div>"]],
"hmac":[["impl&lt;D&gt; <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"hmac/struct.HmacCore.html\" title=\"struct hmac::HmacCore\">HmacCore</a>&lt;D&gt;<div class=\"where\">where\n    D: <a class=\"trait\" href=\"digest/core_api/wrapper/trait.CoreProxy.html\" title=\"trait digest::core_api::wrapper::CoreProxy\">CoreProxy</a>,\n    D::<a class=\"associatedtype\" href=\"digest/core_api/wrapper/trait.CoreProxy.html#associatedtype.Core\" title=\"type digest::core_api::wrapper::CoreProxy::Core\">Core</a>: <a class=\"trait\" href=\"digest/digest/trait.HashMarker.html\" title=\"trait digest::digest::HashMarker\">HashMarker</a> + <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> + <a class=\"trait\" href=\"digest/core_api/trait.UpdateCore.html\" title=\"trait digest::core_api::UpdateCore\">UpdateCore</a> + <a class=\"trait\" href=\"digest/core_api/trait.FixedOutputCore.html\" title=\"trait digest::core_api::FixedOutputCore\">FixedOutputCore</a> + <a class=\"trait\" href=\"digest/core_api/trait.BufferKindUser.html\" title=\"trait digest::core_api::BufferKindUser\">BufferKindUser</a>&lt;BufferKind = <a class=\"struct\" href=\"block_buffer/struct.Eager.html\" title=\"struct block_buffer::Eager\">Eager</a>&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.80.1/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.80.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,\n    &lt;D::<a class=\"associatedtype\" href=\"digest/core_api/wrapper/trait.CoreProxy.html#associatedtype.Core\" title=\"type digest::core_api::wrapper::CoreProxy::Core\">Core</a> as <a class=\"trait\" href=\"crypto_common/trait.BlockSizeUser.html\" title=\"trait crypto_common::BlockSizeUser\">BlockSizeUser</a>&gt;::<a class=\"associatedtype\" href=\"crypto_common/trait.BlockSizeUser.html#associatedtype.BlockSize\" title=\"type crypto_common::BlockSizeUser::BlockSize\">BlockSize</a>: <a class=\"trait\" href=\"typenum/type_operators/trait.IsLess.html\" title=\"trait typenum::type_operators::IsLess\">IsLess</a>&lt;<a class=\"type\" href=\"typenum/generated/consts/type.U256.html\" title=\"type typenum::generated::consts::U256\">U256</a>&gt;,\n    <a class=\"type\" href=\"typenum/operator_aliases/type.Le.html\" title=\"type typenum::operator_aliases::Le\">Le</a>&lt;&lt;D::<a class=\"associatedtype\" href=\"digest/core_api/wrapper/trait.CoreProxy.html#associatedtype.Core\" title=\"type digest::core_api::wrapper::CoreProxy::Core\">Core</a> as <a class=\"trait\" href=\"crypto_common/trait.BlockSizeUser.html\" title=\"trait crypto_common::BlockSizeUser\">BlockSizeUser</a>&gt;::<a class=\"associatedtype\" href=\"crypto_common/trait.BlockSizeUser.html#associatedtype.BlockSize\" title=\"type crypto_common::BlockSizeUser::BlockSize\">BlockSize</a>, <a class=\"type\" href=\"typenum/generated/consts/type.U256.html\" title=\"type typenum::generated::consts::U256\">U256</a>&gt;: <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,</div>"]],
"sha1":[["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"sha1/struct.Sha1Core.html\" title=\"struct sha1::Sha1Core\">Sha1Core</a>"]],
"sha2":[["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"sha2/struct.Sha256VarCore.html\" title=\"struct sha2::Sha256VarCore\">Sha256VarCore</a>"],["impl <a class=\"trait\" href=\"crypto_common/trait.AlgorithmName.html\" title=\"trait crypto_common::AlgorithmName\">AlgorithmName</a> for <a class=\"struct\" href=\"sha2/struct.Sha512VarCore.html\" title=\"struct sha2::Sha512VarCore\">Sha512VarCore</a>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()