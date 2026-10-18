# Service log search

Administration → **Service logs** combines events from all services, newest
first. Filter by service or level and search event text, timestamps, service
names, levels or process IDs. **Load more** reads older retained events; it
also continues a sparse search if the per-request scan budget is reached.

The log table grows with the viewport height and uses compact rows so more
events remain visible. Its header stays in place while scrolling, and long
event text wraps. Filters and **Load more** remain available above and below
the table; short screens can scroll the page as needed.

Select `auth` and search an IP to inspect authentication successes, failures,
blocked attempts and ban changes. Entries include the protocol and attempted
account without credentials. See [login security and IP bans](security.md).

Pages use a snapshot of file positions, so new events do not shift later
pages. Refresh starts a new snapshot. Retention settings still apply: a file
removed by rotation while browsing cannot be recovered by pagination. The
page reports that condition and suggests refreshing.

`GET /api/admin/logs` requires `logs:read` or an administrator session.
Optional query parameters are `service`, `level`, `limit` (1–500, default 100),
`q` (up to 256 UTF-8 bytes), and `cursor`. URL-encode query values. Treat
`next_cursor` as opaque and send it with the same filters to fetch another
page; an empty value marks the end. `entries` contains the current page,
`scan_limited` indicates the bounded scan was exhausted, and `rotated`
indicates snapshot files expired. Search compares ASCII letters without case
and preserves other UTF-8 text for exact substring matching.

Only generated service log paths are read. A request returns at most 500
events, scans at most 16 MiB, and does not return configured service secrets.
