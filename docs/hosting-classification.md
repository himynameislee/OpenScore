# Hosting classification

Organizations rarely run everything they have under their domain. `autodiscover.example.com`
points at Microsoft 365, `go.example.com` at a marketing platform, `www.example.com` sits behind a
CDN. Scoring an organization for settings only its provider can change is unfair, and port-scanning
a provider's shared IPs isn't in anyone's authorization. So OpenScore classifies every host and
treats each class differently.

## The classes

| Class | Meaning | Scored | Port scan | Exposure probes, nuclei, testssl.sh, screenshots |
|---|---|---|---|---|
| **owned** | Infrastructure the organization runs: its own IP space, or a hosting provider OpenScore doesn't recognize | Yes | Yes | Yes |
| **cloud** | IaaS/PaaS the organization configures itself (Azure, AWS, Google Cloud, DigitalOcean…) | Yes | Yes | Yes |
| **cdn** | A CDN or edge proxy in front of the organization's site (Cloudflare, Akamai, Azure Front Door, CloudFront…) | Yes | No, unless `--scan-cdn` | Yes |
| **saas** | A third-party service the organization uses but doesn't run (Microsoft 365, Salesforce, Okta, HubSpot, email senders…) | **No**, listed separately | No | No |
| **unknown** | No hosting information could be found | Yes | Yes | Yes |

Headers, cookies and TLS on a CDN host are still the organization's responsibility (they configure
the CDN), so CDN hosts are scored; only the shared IPs are left alone.

## How a host is classified

In this order, first match wins:

1. **CNAME to a known SaaS service.** If any name in the host's CNAME chain ends in a known SaaS
   suffix (`outlook.com`, `sharepoint.com`, `force.com`, `okta.com`, `hubspot.net`,
   `sendgrid.net`, `github.io`…), the host is **saas**. Suffixes are matched on whole DNS labels, so
   `notoutlook.com` doesn't match `outlook.com`.
2. **CNAME to a known CDN.** `azurefd.net`, `cloudfront.net`, `akamaiedge.net`, `fastly.net`,
   `cdn.cloudflare.net` and similar make it **cdn**.
3. **Who owns the IP.** OpenScore looks up each IP's network (ASN) and its owner's name through
   Team Cymru, and maps known names to a class: Cloudflare or Akamai → cdn, Amazon or Google →
   cloud, Shopify or Zendesk → saas, and so on. A host whose IPs all belong to SaaS providers is
   saas; otherwise the first of cdn, cloud, owned found among its IPs wins.
4. **Anything else** is **owned** when the IP owner is unrecognized (dedicated or colocation
   hosting), and **unknown** when there's no ownership data at all.

### Microsoft

Microsoft's network carries both Microsoft 365 and customers' own Azure resources. Azure VMs,
gateways and App Service apps are the customer's to configure, so **a Microsoft IP means cloud**.
Microsoft 365 is recognized by its CNAMEs instead (`outlook.com`, `sharepoint.com`,
`lync.com`…), and Azure Front Door by `azurefd.net`.

## Overriding it

- **A host you name explicitly** with `--hosts` or `--url` is always assessed, whatever its class.
  Use this when a SaaS-classified host is actually something the organization runs.
- **`--scan-cdn`** port-scans CDN and SaaS IPs too. Only use it when the authorization covers
  those IPs, for example a dedicated CDN origin range.
- **`--exclude`** drops a host completely.

The class of every host is shown in the report's **Asset inventory**, with the ASN owner it was
based on. If a host is misclassified and the provider is common, please
[open an issue](https://github.com/himynameislee/OpenScore/issues) so the list can be improved.
