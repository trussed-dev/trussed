(function() {var type_impls = {
"heapless":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Default-for-MpMcQueue%3CT,+N%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/heapless/mpmc.rs.html#189-193\">source</a><a href=\"#impl-Default-for-MpMcQueue%3CT,+N%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.78.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.78.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"heapless/mpmc/struct.MpMcQueue.html\" title=\"struct heapless::mpmc::MpMcQueue\">MpMcQueue</a>&lt;T, N&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.default\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/heapless/mpmc.rs.html#190-192\">source</a><a href=\"#method.default\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.78.0/core/default/trait.Default.html#tymethod.default\" class=\"fn\">default</a>() -&gt; Self</h4></section></summary><div class='docblock'>Returns the “default value” for a type. <a href=\"https://doc.rust-lang.org/1.78.0/core/default/trait.Default.html#tymethod.default\">Read more</a></div></details></div></details>","Default","heapless::mpmc::Q2","heapless::mpmc::Q4","heapless::mpmc::Q8","heapless::mpmc::Q16","heapless::mpmc::Q32","heapless::mpmc::Q64"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-MpMcQueue%3CT,+N%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/heapless/mpmc.rs.html#139-187\">source</a><a href=\"#impl-MpMcQueue%3CT,+N%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.78.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"struct\" href=\"heapless/mpmc/struct.MpMcQueue.html\" title=\"struct heapless::mpmc::MpMcQueue\">MpMcQueue</a>&lt;T, N&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.new\" class=\"method\"><a class=\"src rightside\" href=\"src/heapless/mpmc.rs.html#146-167\">source</a><h4 class=\"code-header\">pub const fn <a href=\"heapless/mpmc/struct.MpMcQueue.html#tymethod.new\" class=\"fn\">new</a>() -&gt; Self</h4></section></summary><div class=\"docblock\"><p>Creates an empty queue</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.dequeue\" class=\"method\"><a class=\"src rightside\" href=\"src/heapless/mpmc.rs.html#170-172\">source</a><h4 class=\"code-header\">pub fn <a href=\"heapless/mpmc/struct.MpMcQueue.html#tymethod.dequeue\" class=\"fn\">dequeue</a>(&amp;self) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.78.0/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;T&gt;</h4></section></summary><div class=\"docblock\"><p>Returns the item in the front of the queue, or <code>None</code> if the queue is empty</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.enqueue\" class=\"method\"><a class=\"src rightside\" href=\"src/heapless/mpmc.rs.html#177-186\">source</a><h4 class=\"code-header\">pub fn <a href=\"heapless/mpmc/struct.MpMcQueue.html#tymethod.enqueue\" class=\"fn\">enqueue</a>(&amp;self, item: T) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.78.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.78.0/core/primitive.unit.html\">()</a>, T&gt;</h4></section></summary><div class=\"docblock\"><p>Adds an <code>item</code> to the end of the queue</p>\n<p>Returns back the <code>item</code> if the queue is full</p>\n</div></details></div></details>",0,"heapless::mpmc::Q2","heapless::mpmc::Q4","heapless::mpmc::Q8","heapless::mpmc::Q16","heapless::mpmc::Q32","heapless::mpmc::Q64"],["<section id=\"impl-Sync-for-MpMcQueue%3CT,+N%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/heapless/mpmc.rs.html#195\">source</a><a href=\"#impl-Sync-for-MpMcQueue%3CT,+N%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.78.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.78.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> for <a class=\"struct\" href=\"heapless/mpmc/struct.MpMcQueue.html\" title=\"struct heapless::mpmc::MpMcQueue\">MpMcQueue</a>&lt;T, N&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.78.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,</div></h3></section>","Sync","heapless::mpmc::Q2","heapless::mpmc::Q4","heapless::mpmc::Q8","heapless::mpmc::Q16","heapless::mpmc::Q32","heapless::mpmc::Q64"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()