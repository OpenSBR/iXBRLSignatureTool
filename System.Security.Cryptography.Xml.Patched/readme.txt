Source copied from tag v3.1.2 https://github.com/dotnet/corefx
Due to the importance of consistently producing and verifying valid signatures for currently used .NET framework versions, this copy has been included with patches applied.

Fixes applied:
- Inclusive C14N propagates xml:* attributes from excluded ancestor nodes to all descendents; it does not track if these attributes have been rendered already.
  For example:
  <root xml:lang="en">
    <item xml:lang="nl">
      <foo />
    </item>
    <item>
      <bar />
    </item>
  </root>
  with inc-C14N applied to the <item> elements incorrectly results in:
    <item xml:lang="nl">
      <foo xml:lang="en"></foo>
    </item>
    <item xml:lang="en">
      <bar xml:lang="en"></bar>
    </item>

- Exclusive C14N includes all ancestor xml:* attributes on document fragments. These attributes are propagated before any transform; while inclusive C14N should
  include them, exclusive should not, but it can no longer be determined where these attributes came from.
  For example:
  <root xml:lang="en">
    <item id="foo">
      <foo />
    </item>
  </root>
  with a reference to #foo and a transform of exc-C14N incorrectly results in:
    <item id="foo" xml:lang="en">
      <foo></foo>
    </item>

- xml:* attributes are not propagated if an attribute with the same local name is present; xml:id and id are not identical.
  For example:
  <root xml:lang="en">
    <item />
    <item lang="sv" />
  </root>
  with inc-C14N applied to the items results in:
    <item xml:lang="en"></item>     (correct)
    <item lang="sv"></item>         (incorrect)


Additional changes:
- Objects added to the signature could be referenced by ds:Id only on their root node. They are now located by the XPath expression //*[@Id=...]


Not fixed:
- xml:* attributes and namespace definitions with the same name cause an exception (e.g. xml:lang and xmlns:lang).
- C14N performance is very poor, probably due to the creation of multiple copies of the document.
- No support for inclusive C14N 1.1
