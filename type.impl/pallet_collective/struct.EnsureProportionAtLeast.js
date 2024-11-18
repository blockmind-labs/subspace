(function() {
    var type_impls = Object.fromEntries([["subspace_runtime",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-EnsureOrigin%3CO%3E-for-EnsureProportionAtLeast%3CAccountId,+I,+N,+D%3E\" class=\"impl\"><a href=\"#impl-EnsureOrigin%3CO%3E-for-EnsureProportionAtLeast%3CAccountId,+I,+N,+D%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;O, AccountId, I, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>, const D: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>&gt; EnsureOrigin&lt;O&gt; for EnsureProportionAtLeast&lt;AccountId, I, N, D&gt;<div class=\"where\">where\n    O: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;RawOrigin&lt;AccountId, I&gt;, O&gt;&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;RawOrigin&lt;AccountId, I&gt;&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Success\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Success\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">Success</a> = <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a></h4></section></summary><div class='docblock'>A return type.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.try_origin\" class=\"method trait-impl\"><a href=\"#method.try_origin\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">try_origin</a>(\n    o: O,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;&lt;EnsureProportionAtLeast&lt;AccountId, I, N, D&gt; as EnsureOrigin&lt;O&gt;&gt;::Success, O&gt;</h4></section></summary><div class='docblock'>Perform the origin check.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ensure_origin\" class=\"method trait-impl\"><a href=\"#method.ensure_origin\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">ensure_origin</a>(o: OuterOrigin) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self::Success, BadOrigin&gt;</h4></section></summary><div class='docblock'>Perform the origin check.</div></details></div></details>","EnsureOrigin<O>","subspace_runtime::AllCouncil","subspace_runtime::TwoThirdsCouncil","subspace_runtime::HalfCouncil"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-EnsureOriginWithArg%3CO,+T%3E-for-EnsureProportionAtLeast%3CAccountId,+I,+N,+D%3E\" class=\"impl\"><a href=\"#impl-EnsureOriginWithArg%3CO,+T%3E-for-EnsureProportionAtLeast%3CAccountId,+I,+N,+D%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;O, I, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>, const D: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>, AccountId, T&gt; EnsureOriginWithArg&lt;O, T&gt; for EnsureProportionAtLeast&lt;AccountId, I, N, D&gt;<div class=\"where\">where\n    O: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;RawOrigin&lt;AccountId, I&gt;, O&gt;&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;RawOrigin&lt;AccountId, I&gt;&gt;,\n    I: 'static,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Success\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Success\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">Success</a> = &lt;EnsureProportionAtLeast&lt;AccountId, I, N, D&gt; as EnsureOrigin&lt;O&gt;&gt;::Success</h4></section></summary><div class='docblock'>A return type.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.try_origin\" class=\"method trait-impl\"><a href=\"#method.try_origin\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">try_origin</a>(\n    o: O,\n    _: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;T</a>,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;&lt;EnsureProportionAtLeast&lt;AccountId, I, N, D&gt; as EnsureOriginWithArg&lt;O, T&gt;&gt;::Success, O&gt;</h4></section></summary><div class='docblock'>Perform the origin check, returning the origin value if unsuccessful. This allows chaining.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ensure_origin\" class=\"method trait-impl\"><a href=\"#method.ensure_origin\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">ensure_origin</a>(\n    o: OuterOrigin,\n    a: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Argument</a>,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self::Success, BadOrigin&gt;</h4></section></summary><div class='docblock'>Perform the origin check.</div></details></div></details>","EnsureOriginWithArg<O, T>","subspace_runtime::AllCouncil","subspace_runtime::TwoThirdsCouncil","subspace_runtime::HalfCouncil"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[6127]}