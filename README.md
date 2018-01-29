# Filter Options

Burp extension to filter OPTIONS requests from proxy history. This works by adding a header "Content-Type: application/octet-stream" to OPTIONS responses. That mime-type is filtered by the
default proxy history filter.

