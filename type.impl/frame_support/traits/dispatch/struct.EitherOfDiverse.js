(function() {
    var type_impls = Object.fromEntries([["subspace_runtime",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-EnsureOrigin%3COuterOrigin%3E-for-EitherOfDiverse%3CL,+R%3E\" class=\"impl\"><a href=\"#impl-EnsureOrigin%3COuterOrigin%3E-for-EitherOfDiverse%3CL,+R%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;OuterOrigin, L, R&gt; EnsureOrigin&lt;OuterOrigin&gt; for EitherOfDiverse&lt;L, R&gt;<div class=\"where\">where\n    L: EnsureOrigin&lt;OuterOrigin&gt;,\n    R: EnsureOrigin&lt;OuterOrigin&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Success\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Success\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">Success</a> = <a class=\"enum\" href=\"https://docs.rs/either/1/either/enum.Either.html\" title=\"enum either::Either\">Either</a>&lt;&lt;L as EnsureOrigin&lt;OuterOrigin&gt;&gt;::Success, &lt;R as EnsureOrigin&lt;OuterOrigin&gt;&gt;::Success&gt;</h4></section></summary><div class='docblock'>A return type.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.try_origin\" class=\"method trait-impl\"><a href=\"#method.try_origin\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">try_origin</a>(\n    o: OuterOrigin,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;&lt;EitherOfDiverse&lt;L, R&gt; as EnsureOrigin&lt;OuterOrigin&gt;&gt;::Success, OuterOrigin&gt;</h4></section></summary><div class='docblock'>Perform the origin check.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ensure_origin\" class=\"method trait-impl\"><a href=\"#method.ensure_origin\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">ensure_origin</a>(o: OuterOrigin) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self::Success, BadOrigin&gt;</h4></section></summary><div class='docblock'>Perform the origin check.</div></details></div></details>","EnsureOrigin<OuterOrigin>","subspace_runtime::EnsureRootOr"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-EnsureOriginWithArg%3COuterOrigin,+Argument%3E-for-EitherOfDiverse%3CL,+R%3E\" class=\"impl\"><a href=\"#impl-EnsureOriginWithArg%3COuterOrigin,+Argument%3E-for-EitherOfDiverse%3CL,+R%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;OuterOrigin, L, R, Argument&gt; EnsureOriginWithArg&lt;OuterOrigin, Argument&gt; for EitherOfDiverse&lt;L, R&gt;<div class=\"where\">where\n    L: EnsureOriginWithArg&lt;OuterOrigin, Argument&gt;,\n    R: EnsureOriginWithArg&lt;OuterOrigin, Argument&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Success\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Success\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">Success</a> = <a class=\"enum\" href=\"https://docs.rs/either/1/either/enum.Either.html\" title=\"enum either::Either\">Either</a>&lt;&lt;L as EnsureOriginWithArg&lt;OuterOrigin, Argument&gt;&gt;::Success, &lt;R as EnsureOriginWithArg&lt;OuterOrigin, Argument&gt;&gt;::Success&gt;</h4></section></summary><div class='docblock'>A return type.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.try_origin\" class=\"method trait-impl\"><a href=\"#method.try_origin\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">try_origin</a>(\n    o: OuterOrigin,\n    a: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Argument</a>,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;&lt;EitherOfDiverse&lt;L, R&gt; as EnsureOriginWithArg&lt;OuterOrigin, Argument&gt;&gt;::Success, OuterOrigin&gt;</h4></section></summary><div class='docblock'>Perform the origin check, returning the origin value if unsuccessful. This allows chaining.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ensure_origin\" class=\"method trait-impl\"><a href=\"#method.ensure_origin\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">ensure_origin</a>(\n    o: OuterOrigin,\n    a: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Argument</a>,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self::Success, BadOrigin&gt;</h4></section></summary><div class='docblock'>Perform the origin check.</div></details></div></details>","EnsureOriginWithArg<OuterOrigin, Argument>","subspace_runtime::EnsureRootOr"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[5066]}