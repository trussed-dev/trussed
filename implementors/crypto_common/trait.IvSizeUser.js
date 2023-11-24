(function() {var implementors = {
"cbc":[["impl&lt;C&gt; <a class=\"trait\" href=\"crypto_common/trait.IvSizeUser.html\" title=\"trait crypto_common::IvSizeUser\">IvSizeUser</a> for <a class=\"struct\" href=\"cbc/struct.Encryptor.html\" title=\"struct cbc::Encryptor\">Encryptor</a>&lt;C&gt;<span class=\"where fmt-newline\">where\n    C: <a class=\"trait\" href=\"cipher/block/trait.BlockEncryptMut.html\" title=\"trait cipher::block::BlockEncryptMut\">BlockEncryptMut</a> + <a class=\"trait\" href=\"cipher/block/trait.BlockCipher.html\" title=\"trait cipher::block::BlockCipher\">BlockCipher</a>,</span>"],["impl&lt;C&gt; <a class=\"trait\" href=\"crypto_common/trait.IvSizeUser.html\" title=\"trait crypto_common::IvSizeUser\">IvSizeUser</a> for <a class=\"struct\" href=\"cbc/struct.Decryptor.html\" title=\"struct cbc::Decryptor\">Decryptor</a>&lt;C&gt;<span class=\"where fmt-newline\">where\n    C: <a class=\"trait\" href=\"cipher/block/trait.BlockDecryptMut.html\" title=\"trait cipher::block::BlockDecryptMut\">BlockDecryptMut</a> + <a class=\"trait\" href=\"cipher/block/trait.BlockCipher.html\" title=\"trait cipher::block::BlockCipher\">BlockCipher</a>,</span>"]],
"chacha20":[["impl <a class=\"trait\" href=\"crypto_common/trait.IvSizeUser.html\" title=\"trait crypto_common::IvSizeUser\">IvSizeUser</a> for <a class=\"struct\" href=\"chacha20/struct.ChaCha20LegacyCore.html\" title=\"struct chacha20::ChaCha20LegacyCore\">ChaCha20LegacyCore</a>"],["impl&lt;R: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>&gt; <a class=\"trait\" href=\"crypto_common/trait.IvSizeUser.html\" title=\"trait crypto_common::IvSizeUser\">IvSizeUser</a> for <a class=\"struct\" href=\"chacha20/struct.XChaChaCore.html\" title=\"struct chacha20::XChaChaCore\">XChaChaCore</a>&lt;R&gt;"],["impl&lt;R: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>&gt; <a class=\"trait\" href=\"crypto_common/trait.IvSizeUser.html\" title=\"trait crypto_common::IvSizeUser\">IvSizeUser</a> for <a class=\"struct\" href=\"chacha20/struct.ChaChaCore.html\" title=\"struct chacha20::ChaChaCore\">ChaChaCore</a>&lt;R&gt;"]],
"cipher":[["impl&lt;T: <a class=\"trait\" href=\"cipher/trait.IvSizeUser.html\" title=\"trait cipher::IvSizeUser\">IvSizeUser</a> + <a class=\"trait\" href=\"cipher/trait.BlockSizeUser.html\" title=\"trait cipher::BlockSizeUser\">BlockSizeUser</a>&gt; <a class=\"trait\" href=\"cipher/trait.IvSizeUser.html\" title=\"trait cipher::IvSizeUser\">IvSizeUser</a> for <a class=\"struct\" href=\"cipher/struct.StreamCipherCoreWrapper.html\" title=\"struct cipher::StreamCipherCoreWrapper\">StreamCipherCoreWrapper</a>&lt;T&gt;<span class=\"where fmt-newline\">where\n    T::<a class=\"associatedtype\" href=\"cipher/trait.BlockSizeUser.html#associatedtype.BlockSize\" title=\"type cipher::BlockSizeUser::BlockSize\">BlockSize</a>: <a class=\"trait\" href=\"typenum/type_operators/trait.IsLess.html\" title=\"trait typenum::type_operators::IsLess\">IsLess</a>&lt;<a class=\"type\" href=\"cipher/consts/type.U256.html\" title=\"type cipher::consts::U256\">U256</a>&gt;,\n    <a class=\"type\" href=\"typenum/operator_aliases/type.Le.html\" title=\"type typenum::operator_aliases::Le\">Le</a>&lt;T::<a class=\"associatedtype\" href=\"cipher/trait.BlockSizeUser.html#associatedtype.BlockSize\" title=\"type cipher::BlockSizeUser::BlockSize\">BlockSize</a>, <a class=\"type\" href=\"cipher/consts/type.U256.html\" title=\"type cipher::consts::U256\">U256</a>&gt;: <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,</span>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()