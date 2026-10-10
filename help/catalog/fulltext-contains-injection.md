# Full-Text Search Injection

> Classic / In-Band · a predicate with its own mini query-language is
> still ordinary SQL injection underneath

**The premise:** an article search box uses SQL Server's full-text
`CONTAINS` predicate so visitors can search with natural phrases, boolean
operators, and proximity terms. The search box's text is concatenated
straight into the `CONTAINS` clause.

**Why it matters:** it's easy to assume a feature with its own rich query
syntax needs special handling to secure. It doesn't — underneath, it's the
exact same UNION-based injection taught at the very start of the catalog.

## Where the name comes from

Named for the SQL Server feature it targets — full-text search's
`CONTAINS`/`FREETEXT` predicates — not a new injection mechanism.
Underneath, this is the same UNION-based SQL injection taught earlier in
the catalog, just reached through a predicate with its own embedded search
language instead of a plain `WHERE` comparison.

## In the app

- Watch a closed `CONTAINS(...)` call hand off cleanly into an ordinary
  `UNION SELECT`.
- Compare a keyword blacklist against the real fix: parameterizing the
  `CONTAINS` search condition directly.
- Challenge: get the article search to return usernames and password
  hashes instead of articles.

## Learn more

- [Microsoft Learn — Query with Full-Text Search](https://learn.microsoft.com/sql/relational-databases/search/query-with-full-text-search)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet)

Related: [UNION-Based Injection](union-based-injection.md) is the
underlying technique this scenario reaches through a different feature.
Back to the **[Attack Catalog](overview.md)**.
