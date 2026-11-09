# dns.netfixpro.in website

Static promotion page for ISP NetControl, with the one-line installer.

| File | Purpose |
|------|---------|
| `index.html` | The page (no build step, no external assets) |
| `install.sh` | One-line installer: `curl -fsSL https://dns.netfixpro.in/install.sh \| sudo bash` |
| `img/` | Screenshots (WebP) |
| `_headers` | Cloudflare: serve `install.sh` as plain text, no caching |

## Publish on Cloudflare

1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Upload your static files**.
2. Name the project (for example `netfixpro-dns`) and upload this `website` folder
   (or the `netfixpro-dns-website.zip` built from it).
3. **Deploy**, then open the project → **Custom domains** → add `dns.netfixpro.in`.
   Cloudflare creates the DNS record and the certificate.
4. Check: `curl -fsSL https://dns.netfixpro.in/install.sh | head` prints the script.

To update the site, upload the folder again as a new deployment.

`install.sh` fetches the License Manager's **public** signing key from
`https://licenses.netfixpro.in:8443/api/v1/public-keys` at install time; no
key is stored in this repository.
