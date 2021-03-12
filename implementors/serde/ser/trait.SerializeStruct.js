(function() {var implementors = {};
implementors["cbor_smol"] = [{"text":"impl&lt;'a, W&gt; SerializeStruct for &amp;'a mut Serializer&lt;W&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;W: Writer,&nbsp;</span>","synthetic":false,"types":[]}];
implementors["postcard"] = [{"text":"impl&lt;'a, F&gt; SerializeStruct for &amp;'a mut Serializer&lt;F&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;F: SerFlavor,&nbsp;</span>","synthetic":false,"types":[]}];
implementors["serde"] = [];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()