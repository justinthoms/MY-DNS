# dns.netfixpro.in website

Static promotion page for ISP NetControl, with the one-line installer.

| File | Purpose |
|------|---------|
| `index.html` | The page (no build step, no external assets) |
| `install.sh` | One-line installer: `curl -fsSL https://dns.netfixpro.in/install.sh \| sudo bash` |
| `img/` | Screenshots (WebP) |
| `_headers` | Cloudflare: serve `install.sh` as plain text, no caching |
| `public-keys.pem` | **You add this before uploading** (not in git, see below) |

## Publish on Cloudflare

1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Upload your static files**.
2. Name the project (for example `netfixpro-dns`) and upload this `website` folder
   (or the `netfixpro-dns-website.zip` built from it).
3. **Deploy**, then open the project → **Custom domains** → add `dns.netfixpro.in`.
   Cloudflare creates the DNS record and the certificate.
4. Check: `curl -fsSL https://dns.netfixpro.in/install.sh | head` prints the script.

To update the site, upload the folder again as a new deployment.

## The signing key (public-keys.pem)

`install.sh` builds the License Manager's **public** signing key into each
installation. It first asks `https://licenses.netfixpro.in:8443/api/v1/public-keys`.
If that fails (for example the certificate there is not publicly trusted),
it uses `https://dns.netfixpro.in/public-keys.pem` instead. Before uploading
the site, save the key into this folder:

```bash
curl -fsSk https://licenses.netfixpro.in:8443/api/v1/public-keys -o website/public-keys.pem
```

It is a public key (it can only check licenses, never create them), but it
is kept out of git on purpose (`.gitignore`), like every other license file.
