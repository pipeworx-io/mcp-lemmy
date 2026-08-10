# @pipeworx/lemmy

[Lemmy](https://join-lemmy.org) federated link-aggregator MCP — communities, posts, comments. Keyless for public reads. Default instance `lemmy.world` (override via `instance` arg).

## Tools

- `posts(community?, sort?, type_?, limit?, page?, instance?)` — list posts
- `post(id, instance?)` — single post
- `comments(post_id?, parent_id?, community?, sort?, max_depth?, limit?, page?, instance?)` — comments
- `communities(type_?, sort?, limit?, page?, instance?)` — list communities
- `community(name_or_id, instance?)` — community metadata
- `site(instance?)` — instance metadata
- `search(q, type_?, listing_type?, sort?, limit?, page?, instance?)` — full search

## Data source

`https://<instance>/api/v3/...` — Lemmy REST API.

## Quick Start

Add to your MCP client (Claude Desktop, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "lemmy": {
      "url": "https://gateway.pipeworx.io/lemmy/mcp"
    }
  }
}
```

Or connect to the full Pipeworx gateway for access to all 1422+ data sources:

```json
{
  "mcpServers": {
    "pipeworx": {
      "url": "https://gateway.pipeworx.io/mcp"
    }
  }
}
```

## Using with ask_pipeworx

Instead of calling tools directly, you can ask questions in plain English:

```
ask_pipeworx({ question: "your question about Lemmy data" })
```

The gateway picks the right tool and fills the arguments automatically.

## More

- [All tools and guides](https://github.com/pipeworx-io/examples)
- [pipeworx.io](https://pipeworx.io)

## License

MIT
