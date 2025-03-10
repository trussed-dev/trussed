(function() {
    var implementors = Object.fromEntries([["crypto_bigint",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"crypto_bigint/limb/struct.Limb.html\" title=\"struct crypto_bigint::limb::Limb\">Limb</a>"],["impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;T&gt;"],["impl&lt;const LIMBS: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.85.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"crypto_bigint/struct.UInt.html\" title=\"struct crypto_bigint::UInt\">UInt</a>&lt;LIMBS&gt;"]]],["delog",[["impl&lt;'a, T, U, S&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"delog/hex/struct.HexStr.html\" title=\"struct delog::hex::HexStr\">HexStr</a>&lt;'a, T, U, S&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/convert/trait.AsRef.html\" title=\"trait core::convert::AsRef\">AsRef</a>&lt;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.85.0/core/primitive.u8.html\">u8</a>]&gt; + ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,\n    U: <a class=\"trait\" href=\"delog/hex/trait.Unsigned.html\" title=\"trait delog::hex::Unsigned\">Unsigned</a>,\n    S: <a class=\"trait\" href=\"delog/hex/trait.Separator.html\" title=\"trait delog::hex::Separator\">Separator</a>,</div>"]]],["ed25519",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"ed25519/struct.Signature.html\" title=\"struct ed25519::Signature\">Signature</a>"]]],["generic_array",[["impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"generic_array/struct.GenericArray.html\" title=\"struct generic_array::GenericArray\">GenericArray</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.85.0/core/primitive.u8.html\">u8</a>, T&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;T&gt; + <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.85.0/core/primitive.u8.html\">u8</a>&gt;,\n    &lt;T as <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;T&gt;&gt;::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.85.0/core/ops/arith/trait.Add.html#associatedtype.Output\" title=\"type core::ops::arith::Add::Output\">Output</a>: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.85.0/core/primitive.u8.html\">u8</a>&gt;,</div>"]]],["littlefs2_core",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"littlefs2_core/struct.FileOpenFlags.html\" title=\"struct littlefs2_core::FileOpenFlags\">FileOpenFlags</a>"]]],["trussed",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"trussed/key/struct.Flags.html\" title=\"struct trussed::key::Flags\">Flags</a>"]]],["zerocopy",[["impl&lt;O: <a class=\"trait\" href=\"zerocopy/byteorder/trait.ByteOrder.html\" title=\"trait zerocopy::byteorder::ByteOrder\">ByteOrder</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"zerocopy/byteorder/struct.I128.html\" title=\"struct zerocopy::byteorder::I128\">I128</a>&lt;O&gt;"],["impl&lt;O: <a class=\"trait\" href=\"zerocopy/byteorder/trait.ByteOrder.html\" title=\"trait zerocopy::byteorder::ByteOrder\">ByteOrder</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"zerocopy/byteorder/struct.I16.html\" title=\"struct zerocopy::byteorder::I16\">I16</a>&lt;O&gt;"],["impl&lt;O: <a class=\"trait\" href=\"zerocopy/byteorder/trait.ByteOrder.html\" title=\"trait zerocopy::byteorder::ByteOrder\">ByteOrder</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"zerocopy/byteorder/struct.I32.html\" title=\"struct zerocopy::byteorder::I32\">I32</a>&lt;O&gt;"],["impl&lt;O: <a class=\"trait\" href=\"zerocopy/byteorder/trait.ByteOrder.html\" title=\"trait zerocopy::byteorder::ByteOrder\">ByteOrder</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"zerocopy/byteorder/struct.I64.html\" title=\"struct zerocopy::byteorder::I64\">I64</a>&lt;O&gt;"],["impl&lt;O: <a class=\"trait\" href=\"zerocopy/byteorder/trait.ByteOrder.html\" title=\"trait zerocopy::byteorder::ByteOrder\">ByteOrder</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"zerocopy/byteorder/struct.Isize.html\" title=\"struct zerocopy::byteorder::Isize\">Isize</a>&lt;O&gt;"],["impl&lt;O: <a class=\"trait\" href=\"zerocopy/byteorder/trait.ByteOrder.html\" title=\"trait zerocopy::byteorder::ByteOrder\">ByteOrder</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"zerocopy/byteorder/struct.U128.html\" title=\"struct zerocopy::byteorder::U128\">U128</a>&lt;O&gt;"],["impl&lt;O: <a class=\"trait\" href=\"zerocopy/byteorder/trait.ByteOrder.html\" title=\"trait zerocopy::byteorder::ByteOrder\">ByteOrder</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"zerocopy/byteorder/struct.U16.html\" title=\"struct zerocopy::byteorder::U16\">U16</a>&lt;O&gt;"],["impl&lt;O: <a class=\"trait\" href=\"zerocopy/byteorder/trait.ByteOrder.html\" title=\"trait zerocopy::byteorder::ByteOrder\">ByteOrder</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"zerocopy/byteorder/struct.U32.html\" title=\"struct zerocopy::byteorder::U32\">U32</a>&lt;O&gt;"],["impl&lt;O: <a class=\"trait\" href=\"zerocopy/byteorder/trait.ByteOrder.html\" title=\"trait zerocopy::byteorder::ByteOrder\">ByteOrder</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"zerocopy/byteorder/struct.U64.html\" title=\"struct zerocopy::byteorder::U64\">U64</a>&lt;O&gt;"],["impl&lt;O: <a class=\"trait\" href=\"zerocopy/byteorder/trait.ByteOrder.html\" title=\"trait zerocopy::byteorder::ByteOrder\">ByteOrder</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/fmt/trait.LowerHex.html\" title=\"trait core::fmt::LowerHex\">LowerHex</a> for <a class=\"struct\" href=\"zerocopy/byteorder/struct.Usize.html\" title=\"struct zerocopy::byteorder::Usize\">Usize</a>&lt;O&gt;"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[1108,966,275,1402,308,272,4173]}