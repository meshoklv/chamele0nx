# Cover site

Whatever lives in this directory is what an unauthenticated visitor sees
when they open `https://your-domain/` in a browser. It is served by
`chamele0nx-server -cover-dir`.

**Replace it.** The files here are a deliberately bland placeholder so
the server does something sane out of the box. Shipping the sample
site unchanged makes every deployment of this project look identical,
which is exactly the fingerprint the protocol exists to avoid.

A good cover site:

- looks like a product someone would plausibly host on that domain,
  and matches the domain name;
- has a login form that fails like a real login form fails, not one
  that returns the same response for every input;
- serves a handful of static assets (CSS, a font, a logo), so a page
  load produces a burst of requests rather than a single one;
- returns a normal 404 for unknown paths;
- carries no reference to VPNs, proxies, censorship, or this project.

The simplest strong option is to point `-cover-dir` at a copy of a real
static site you actually run.
