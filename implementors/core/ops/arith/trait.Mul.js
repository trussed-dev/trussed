(function() {var implementors = {
"crypto_bigint":[["impl&lt;const LIMBS:&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.68.2/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.Checked.html\" title=\"struct crypto_bigint::Checked\">Checked</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.UInt.html\" title=\"struct crypto_bigint::UInt\">UInt</a>&lt;LIMBS&gt;&gt;&gt; for <a class=\"struct\" href=\"crypto_bigint/struct.Checked.html\" title=\"struct crypto_bigint::Checked\">Checked</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.UInt.html\" title=\"struct crypto_bigint::UInt\">UInt</a>&lt;LIMBS&gt;&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/limb/struct.Limb.html\" title=\"struct crypto_bigint::limb::Limb\">Limb</a>&gt;&gt; for <a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/limb/struct.Limb.html\" title=\"struct crypto_bigint::limb::Limb\">Limb</a>&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;<a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/limb/struct.Limb.html\" title=\"struct crypto_bigint::limb::Limb\">Limb</a>&gt;&gt; for <a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/limb/struct.Limb.html\" title=\"struct crypto_bigint::limb::Limb\">Limb</a>&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/limb/struct.Limb.html\" title=\"struct crypto_bigint::limb::Limb\">Limb</a>&gt;&gt; for &amp;<a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/limb/struct.Limb.html\" title=\"struct crypto_bigint::limb::Limb\">Limb</a>&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;<a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/limb/struct.Limb.html\" title=\"struct crypto_bigint::limb::Limb\">Limb</a>&gt;&gt; for &amp;<a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/limb/struct.Limb.html\" title=\"struct crypto_bigint::limb::Limb\">Limb</a>&gt;"],["impl&lt;const LIMBS:&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.68.2/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.UInt.html\" title=\"struct crypto_bigint::UInt\">UInt</a>&lt;LIMBS&gt;&gt;&gt; for <a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.UInt.html\" title=\"struct crypto_bigint::UInt\">UInt</a>&lt;LIMBS&gt;&gt;"],["impl&lt;const LIMBS:&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.68.2/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;<a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.UInt.html\" title=\"struct crypto_bigint::UInt\">UInt</a>&lt;LIMBS&gt;&gt;&gt; for <a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.UInt.html\" title=\"struct crypto_bigint::UInt\">UInt</a>&lt;LIMBS&gt;&gt;"],["impl&lt;const LIMBS:&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.68.2/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.UInt.html\" title=\"struct crypto_bigint::UInt\">UInt</a>&lt;LIMBS&gt;&gt;&gt; for &amp;<a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.UInt.html\" title=\"struct crypto_bigint::UInt\">UInt</a>&lt;LIMBS&gt;&gt;"],["impl&lt;const LIMBS:&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.68.2/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;<a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.UInt.html\" title=\"struct crypto_bigint::UInt\">UInt</a>&lt;LIMBS&gt;&gt;&gt; for &amp;<a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.UInt.html\" title=\"struct crypto_bigint::UInt\">UInt</a>&lt;LIMBS&gt;&gt;"]],
"elliptic_curve":[],
"half":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"half/struct.bf16.html\" title=\"struct half::bf16\">bf16</a>&gt; for <a class=\"struct\" href=\"half/struct.bf16.html\" title=\"struct half::bf16\">bf16</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;<a class=\"struct\" href=\"half/struct.bf16.html\" title=\"struct half::bf16\">bf16</a>&gt; for <a class=\"struct\" href=\"half/struct.bf16.html\" title=\"struct half::bf16\">bf16</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;<a class=\"struct\" href=\"half/struct.bf16.html\" title=\"struct half::bf16\">bf16</a>&gt; for &amp;<a class=\"struct\" href=\"half/struct.bf16.html\" title=\"struct half::bf16\">bf16</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"half/struct.bf16.html\" title=\"struct half::bf16\">bf16</a>&gt; for &amp;<a class=\"struct\" href=\"half/struct.bf16.html\" title=\"struct half::bf16\">bf16</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"half/struct.f16.html\" title=\"struct half::f16\">f16</a>&gt; for <a class=\"struct\" href=\"half/struct.f16.html\" title=\"struct half::f16\">f16</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;<a class=\"struct\" href=\"half/struct.f16.html\" title=\"struct half::f16\">f16</a>&gt; for <a class=\"struct\" href=\"half/struct.f16.html\" title=\"struct half::f16\">f16</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;<a class=\"struct\" href=\"half/struct.f16.html\" title=\"struct half::f16\">f16</a>&gt; for &amp;<a class=\"struct\" href=\"half/struct.f16.html\" title=\"struct half::f16\">f16</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"half/struct.f16.html\" title=\"struct half::f16\">f16</a>&gt; for &amp;<a class=\"struct\" href=\"half/struct.f16.html\" title=\"struct half::f16\">f16</a>"]],
"p256":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>&gt; for <a class=\"struct\" href=\"p256/struct.AffinePoint.html\" title=\"struct p256::AffinePoint\">AffinePoint</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;<a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>&gt; for <a class=\"struct\" href=\"p256/struct.AffinePoint.html\" title=\"struct p256::AffinePoint\">AffinePoint</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>&gt; for <a class=\"struct\" href=\"p256/struct.ProjectivePoint.html\" title=\"struct p256::ProjectivePoint\">ProjectivePoint</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;<a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>&gt; for &amp;<a class=\"struct\" href=\"p256/struct.ProjectivePoint.html\" title=\"struct p256::ProjectivePoint\">ProjectivePoint</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;<a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>&gt; for <a class=\"struct\" href=\"p256/struct.ProjectivePoint.html\" title=\"struct p256::ProjectivePoint\">ProjectivePoint</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>&gt; for <a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;<a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>&gt; for &amp;<a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;<a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>&gt; for <a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>"]],
"salty":[["impl&lt;'a, 'b&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;'b <a class=\"struct\" href=\"salty/struct.EdwardsPoint.html\" title=\"struct salty::EdwardsPoint\">EdwardsPoint</a>&gt; for &amp;'a <a class=\"struct\" href=\"salty/struct.Scalar.html\" title=\"struct salty::Scalar\">Scalar</a>"],["impl&lt;'a, 'b&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;'b <a class=\"struct\" href=\"salty/struct.FieldElement.html\" title=\"struct salty::FieldElement\">FieldElement</a>&gt; for &amp;'a <a class=\"struct\" href=\"salty/struct.FieldElement.html\" title=\"struct salty::FieldElement\">FieldElement</a>"],["impl&lt;'a, 'b&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;'b <a class=\"struct\" href=\"salty/struct.Scalar.html\" title=\"struct salty::Scalar\">Scalar</a>&gt; for &amp;'a <a class=\"struct\" href=\"salty/struct.MontgomeryPoint.html\" title=\"struct salty::MontgomeryPoint\">MontgomeryPoint</a>"],["impl&lt;'a, 'b&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;'b <a class=\"struct\" href=\"salty/struct.MontgomeryPoint.html\" title=\"struct salty::MontgomeryPoint\">MontgomeryPoint</a>&gt; for &amp;'a <a class=\"struct\" href=\"salty/struct.Scalar.html\" title=\"struct salty::Scalar\">Scalar</a>"],["impl&lt;'a, 'b&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;&amp;'b <a class=\"struct\" href=\"salty/struct.Scalar.html\" title=\"struct salty::Scalar\">Scalar</a>&gt; for &amp;'a <a class=\"struct\" href=\"salty/struct.Scalar.html\" title=\"struct salty::Scalar\">Scalar</a>"]],
"typenum":[["impl&lt;I:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Integer.html\" title=\"trait typenum::marker_traits::Integer\">Integer</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;I&gt; for <a class=\"struct\" href=\"typenum/int/struct.Z0.html\" title=\"struct typenum::int::Z0\">Z0</a>"],["impl&lt;U:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/int/struct.Z0.html\" title=\"struct typenum::int::Z0\">Z0</a>&gt; for <a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;U&gt;"],["impl&lt;U:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/int/struct.Z0.html\" title=\"struct typenum::int::Z0\">Z0</a>&gt; for <a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;U&gt;"],["impl&lt;Ul, Ur:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;Ur&gt;&gt; for <a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;Ul&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;Ur&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;Ul as <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;Ur&gt;&gt;::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html#associatedtype.Output\" title=\"type core::ops::arith::Mul::Output\">Output</a>: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,</span>"],["impl&lt;Ul, Ur:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;Ur&gt;&gt; for <a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;Ul&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;Ur&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;Ul as <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;Ur&gt;&gt;::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html#associatedtype.Output\" title=\"type core::ops::arith::Mul::Output\">Output</a>: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,</span>"],["impl&lt;Ul, Ur:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;Ur&gt;&gt; for <a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;Ul&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;Ur&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;Ul as <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;Ur&gt;&gt;::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html#associatedtype.Output\" title=\"type core::ops::arith::Mul::Output\">Output</a>: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,</span>"],["impl&lt;Ul, Ur:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;Ur&gt;&gt; for <a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;Ul&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;Ur&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;Ul as <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;Ur&gt;&gt;::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html#associatedtype.Output\" title=\"type core::ops::arith::Mul::Output\">Output</a>: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,</span>"],["impl&lt;U:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>, B:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Bit.html\" title=\"trait typenum::marker_traits::Bit\">Bit</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;U, B&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a>"],["impl&lt;U:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>, B:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Bit.html\" title=\"trait typenum::marker_traits::Bit\">Bit</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;U, B&gt;"],["impl&lt;U:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>, B:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Bit.html\" title=\"trait typenum::marker_traits::Bit\">Bit</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a>&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;U, B&gt;"],["impl&lt;U:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;U&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a>"],["impl&lt;Ul, B:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Bit.html\" title=\"trait typenum::marker_traits::Bit\">Bit</a>, Ur:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ur, B&gt;&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ul, <a class=\"struct\" href=\"typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ur, B&gt;&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>,</span>"],["impl&lt;Ul, B:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Bit.html\" title=\"trait typenum::marker_traits::Bit\">Bit</a>, Ur:&nbsp;<a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ur, B&gt;&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ul, <a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ur, B&gt;&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"type\" href=\"typenum/operator_aliases/type.Prod.html\" title=\"type typenum::operator_aliases::Prod\">Prod</a>&lt;Ul, <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ur, B&gt;&gt;, <a class=\"struct\" href=\"typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ur, B&gt;&gt;,</span>"],["impl&lt;Rhs&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;Rhs&gt; for <a class=\"struct\" href=\"typenum/array/struct.ATerm.html\" title=\"struct typenum::array::ATerm\">ATerm</a>"],["impl&lt;V, A, Rhs&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;Rhs&gt; for <a class=\"struct\" href=\"typenum/array/struct.TArr.html\" title=\"struct typenum::array::TArr\">TArr</a>&lt;V, A&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;V: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;Rhs&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;A: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;Rhs&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;Rhs: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>,</span>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/array/struct.ATerm.html\" title=\"struct typenum::array::ATerm\">ATerm</a>&gt; for <a class=\"struct\" href=\"typenum/int/struct.Z0.html\" title=\"struct typenum::int::Z0\">Z0</a>"],["impl&lt;U&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/array/struct.ATerm.html\" title=\"struct typenum::array::ATerm\">ATerm</a>&gt; for <a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;U&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;U: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,</span>"],["impl&lt;U&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/array/struct.ATerm.html\" title=\"struct typenum::array::ATerm\">ATerm</a>&gt; for <a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;U&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;U: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,</span>"],["impl&lt;V, A&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/array/struct.TArr.html\" title=\"struct typenum::array::TArr\">TArr</a>&lt;V, A&gt;&gt; for <a class=\"struct\" href=\"typenum/int/struct.Z0.html\" title=\"struct typenum::int::Z0\">Z0</a><span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"typenum/int/struct.Z0.html\" title=\"struct typenum::int::Z0\">Z0</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;A&gt;,</span>"],["impl&lt;V, A, U&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/array/struct.TArr.html\" title=\"struct typenum::array::TArr\">TArr</a>&lt;V, A&gt;&gt; for <a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;U&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;U: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;U&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;A&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;V&gt;,</span>"],["impl&lt;V, A, U&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;<a class=\"struct\" href=\"typenum/array/struct.TArr.html\" title=\"struct typenum::array::TArr\">TArr</a>&lt;V, A&gt;&gt; for <a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;U&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;U: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;U&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;A&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.68.2/core/ops/arith/trait.Mul.html\" title=\"trait core::ops::arith::Mul\">Mul</a>&lt;V&gt;,</span>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()