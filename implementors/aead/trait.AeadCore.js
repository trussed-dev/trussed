(function() {var implementors = {};
implementors["chacha20poly1305"] = [{"text":"impl&lt;C, N&gt; <a class=\"trait\" href=\"aead/trait.AeadCore.html\" title=\"trait aead::AeadCore\">AeadCore</a> for <a class=\"struct\" href=\"chacha20poly1305/struct.ChaChaPoly1305.html\" title=\"struct chacha20poly1305::ChaChaPoly1305\">ChaChaPoly1305</a>&lt;C, N&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: <a class=\"trait\" href=\"cipher/common/trait.NewCipher.html\" title=\"trait cipher::common::NewCipher\">NewCipher</a>&lt;KeySize = <a class=\"type\" href=\"typenum/generated/consts/type.U32.html\" title=\"type typenum::generated::consts::U32\">U32</a>, NonceSize = N&gt; + <a class=\"trait\" href=\"cipher/stream/trait.StreamCipher.html\" title=\"trait cipher::stream::StreamCipher\">StreamCipher</a> + <a class=\"trait\" href=\"cipher/stream/trait.StreamCipherSeek.html\" title=\"trait cipher::stream::StreamCipherSeek\">StreamCipherSeek</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;N: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.62.1/core/primitive.u8.html\">u8</a>&gt;,&nbsp;</span>","synthetic":false,"types":["chacha20poly1305::ChaChaPoly1305"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()