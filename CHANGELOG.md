# Changelog

## 3.0.0 - 2026-11-23

### Breaking changes

- Requires Ruby 3.2 or newer.
- The RiskIQ provider (`riskiq`, `-dr`) was removed. Its default endpoint, `ws.riskiq.net`, no longer answers, and RiskIQ is now part of
  Microsoft Defender Threat Intelligence. PassiveTotal's `v2` mode was already the same service. Remove any `[riskiq]` section from your config.
- The VirusTotal provider now uses VirusTotal's v3 API (`/api/v3/{domains,ip_addresses}/<item>/resolutions`) instead of v2, and returns at
  most 40 resolutions per query. A `URL` setting that points at the v2 API must be removed or updated. The provider is untested against the
  live service.
- The configuration file is now read with [iniparse](https://rubygems.org/gems/iniparse) instead of `configparser`. The file format and
  location (`~/.passivedns-client`) are unchanged. A file that cannot be parsed now raises an error that names the file.
- TLS certificates are now verified. Every provider used to disable verification (`OpenSSL::SSL::VERIFY_NONE`).
- `PassiveDNS::CLInterface.get_letter_map` was renamed to `letter_map`, and the `$passivedns_providers` global was replaced by
  `PassiveDNS::Client.provider_names`. Providers register themselves by subclassing `PassiveDNS::PassiveDB`.
- The constructor argument of every provider is now named `config` (it is still a positional hash).
- The gem no longer ships the `test/` directory.
- `getoptlong` is now an explicit dependency (it is no longer a default gem in Ruby 3.4), and the `json` and `bundler` dependencies were dropped.

### Fixed

- The SQLite state database (`-f`) built its SQL by interpolating strings, so a `'` in a query or answer broke it and it could be injected.
  It now uses bound parameters.
- Results read back from the SQLite state database had their columns shifted (the query was reported as the source).
- A failed query was marked as failed using the wrong value, so it was never actually marked.
- A non-2xx response from a provider (a bad API key, a rate limit) crashed the query with a JSON parse error and a backtrace. It now
  raises `PassiveDNS::ProviderError` (`DNSDB: HTTP 403: Error: Bad API key`), and `Client#query` prints it and still returns the answers from
  the other providers.
- `Client#timeout=` raised `NoMethodError`, because providers had no `timeout=`.
- DNSDB lost the name of a record that had no trailing dot (`gsub!` returned `nil`).
- OSC, VirusTotal and PassiveTotal put the `security` marking in the `count` field of a result.
- OSC asked for gzip responses and then did not decompress them.
- The PassiveTotal provider no longer prints every response to standard output.
- `TLPSecurityControl#allow` reported `nil` instead of the offending level in its error message.

### Changed

- Linting with RuboCop, CI for Ruby 3.2 to 3.4 and head, and API documentation published to GitHub Pages:
  <https://chrislee35.github.io/passivedns-client/>.
- The tests no longer need a `~/.passivedns-client` file or network access. They use a local fake HTTP server.
- Modernized the gemspec, Rakefile and `.gitignore`, and added `CHANGELOG.md` and `.mailmap`.
