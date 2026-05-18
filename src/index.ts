interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

interface McpToolExport {
  tools: McpToolDefinition[];
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  meter?: { credits: number };
  cost?: Record<string, unknown>;
  provider?: string;
}

/**
 * Lemmy MCP — public reads on any Lemmy instance.
 */


const DEFAULT_INSTANCE = 'lemmy.world';
const UA = 'pipeworx-mcp-lemmy/1.0 (+https://pipeworx.io)';

const tools: McpToolExport['tools'] = [
  {
    name: 'posts',
    description: 'List posts.',
    inputSchema: {
      type: 'object',
      properties: {
        community: { type: 'string', description: 'Community name (e.g. "asklemmy@lemmy.world") or id.' },
        sort: { type: 'string', description: 'Active | Hot | New | Old | TopDay | TopWeek | TopMonth | TopYear | TopAll | MostComments | NewComments' },
        type_: { type: 'string', description: 'All | Local | Subscribed' },
        limit: { type: 'number' },
        page: { type: 'number' },
        instance: { type: 'string' },
      },
    },
  },
  {
    name: 'post',
    description: 'Single post by id.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'number' }, instance: { type: 'string' } },
      required: ['id'],
    },
  },
  {
    name: 'comments',
    description: 'Comments.',
    inputSchema: {
      type: 'object',
      properties: {
        post_id: { type: 'number' },
        parent_id: { type: 'number' },
        community: { type: 'string' },
        sort: { type: 'string' },
        max_depth: { type: 'number' },
        limit: { type: 'number' },
        page: { type: 'number' },
        instance: { type: 'string' },
      },
    },
  },
  {
    name: 'communities',
    description: 'List communities.',
    inputSchema: {
      type: 'object',
      properties: {
        type_: { type: 'string' },
        sort: { type: 'string' },
        limit: { type: 'number' },
        page: { type: 'number' },
        instance: { type: 'string' },
      },
    },
  },
  {
    name: 'community',
    description: 'Community metadata.',
    inputSchema: {
      type: 'object',
      properties: {
        name_or_id: { type: 'string' },
        instance: { type: 'string' },
      },
      required: ['name_or_id'],
    },
  },
  {
    name: 'site',
    description: 'Instance metadata.',
    inputSchema: {
      type: 'object',
      properties: { instance: { type: 'string' } },
    },
  },
  {
    name: 'search',
    description: 'Full search.',
    inputSchema: {
      type: 'object',
      properties: {
        q: { type: 'string' },
        type_: { type: 'string', description: 'All | Comments | Posts | Communities | Users | Url' },
        listing_type: { type: 'string', description: 'All | Local | Subscribed' },
        sort: { type: 'string' },
        limit: { type: 'number' },
        page: { type: 'number' },
        instance: { type: 'string' },
      },
      required: ['q'],
    },
  },
];

async function callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  const inst = pickInstance(args);
  const params = (extra: Record<string, unknown>) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(extra)) {
      if (v == null) continue;
      p.set(k, String(v));
    }
    return p;
  };
  switch (name) {
    case 'posts': {
      const p = params({
        community_name: args.community,
        sort: args.sort,
        type_: args.type_,
        limit: args.limit,
        page: args.page,
      });
      return lemmyGet(inst, `/api/v3/post/list?${p}`);
    }
    case 'post':
      return lemmyGet(inst, `/api/v3/post?id=${(args.id as number) | 0}`);
    case 'comments': {
      const p = params({
        post_id: args.post_id,
        parent_id: args.parent_id,
        community_name: args.community,
        sort: args.sort,
        max_depth: args.max_depth,
        limit: args.limit,
        page: args.page,
      });
      return lemmyGet(inst, `/api/v3/comment/list?${p}`);
    }
    case 'communities': {
      const p = params({
        type_: args.type_,
        sort: args.sort,
        limit: args.limit,
        page: args.page,
      });
      return lemmyGet(inst, `/api/v3/community/list?${p}`);
    }
    case 'community': {
      const id = reqStr(args, 'name_or_id', '"asklemmy"');
      const key = /^\d+$/.test(id) ? `id=${id}` : `name=${encodeURIComponent(id)}`;
      return lemmyGet(inst, `/api/v3/community?${key}`);
    }
    case 'site':
      return lemmyGet(inst, `/api/v3/site`);
    case 'search': {
      const p = params({
        q: reqStr(args, 'q', '"news"'),
        type_: args.type_,
        listing_type: args.listing_type,
        sort: args.sort,
        limit: args.limit,
        page: args.page,
      });
      return lemmyGet(inst, `/api/v3/search?${p}`);
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

function pickInstance(args: Record<string, unknown>): string {
  const i = (args.instance as string | undefined) ?? DEFAULT_INSTANCE;
  return i.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
}

async function lemmyGet(instance: string, path: string): Promise<unknown> {
  const res = await fetch(`https://${instance}${path}`, { headers: { Accept: 'application/json', 'User-Agent': UA } });
  if (res.status === 404) throw new Error('Lemmy: not found');
  if (!res.ok) throw new Error(`Lemmy: ${res.status} ${await res.text().then((t) => t.slice(0, 200))}`);
  return res.json();
}

function reqStr(args: Record<string, unknown>, key: string, example: string): string {
  const v = args[key];
  if (typeof v !== 'string' || !v.trim()) throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
  return v;
}

export default { tools, callTool, meter: { credits: 1 } } satisfies McpToolExport;
