import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse, stringify } from 'yaml';

const root = process.env.NIANYUN_REPO_ROOT || '/opt/nianyun';
const data = process.env.NIANYUN_DATA_DIR || join(root, 'data');
const configDir = join(data, 'config');
mkdirSync(configDir, { recursive: true, mode: 0o700 });
const configPath = join(configDir, 'config.yaml');
const toolsPath = join(configDir, 'tools.env.yaml');
// Initialize once. Console edits and credentials survive recreation/upgrades.
if (!existsSync(configPath)) {
  const cfg = parse(readFileSync(join(root, 'deploy/unified/config.yaml'), 'utf8'));
  cfg.paths = { data_dir: data, tools_env: toolsPath };
  writeFileSync(configPath, stringify(cfg), { mode: 0o600, flag: 'wx' });
}
if (!existsSync(toolsPath)) {
  const env = process.env;
  const tools = parse(readFileSync(join(root, 'tools.env.example.yaml'), 'utf8'));
  tools.asset ||= {};
  tools.arl ||= {};
  tools.blackbox ||= {};
  const key = env.BLACKBOX_AGENT_API_KEY || env.ANTHROPIC_API_KEY || env.ANTHROPIC_AUTH_TOKEN || '';
  const url = env.BLACKBOX_AGENT_BASE_URL || env.ANTHROPIC_BASE_URL || '';
  const model = env.BLACKBOX_AGENT_MODEL || env.ANTHROPIC_MODEL || '';
  if (key) tools.blackbox.BLACKBOX_AGENT_API_KEY = key;
  if (url) tools.blackbox.BLACKBOX_AGENT_BASE_URL = url;
  if (model) tools.blackbox.BLACKBOX_AGENT_MODEL = model;
  if (env.ASSET_AGENT_API_KEY) tools.asset.ASSET_AGENT_API_KEY = env.ASSET_AGENT_API_KEY;
  if (env.ASSET_AGENT_BASE_URL) tools.asset.ASSET_AGENT_BASE_URL = env.ASSET_AGENT_BASE_URL;
  if (env.ASSET_AGENT_MODEL) tools.asset.ASSET_AGENT_MODEL = env.ASSET_AGENT_MODEL;
  if (env.ARL_URL) tools.arl.ARL_URL = env.ARL_URL;
  if (env.ARL_TOKEN) tools.arl.ARL_TOKEN = env.ARL_TOKEN;
  if (env.BURP_PROXY_URL) tools.blackbox.BURP_PROXY_URL = env.BURP_PROXY_URL;
  if (env.BURP_BRIDGE_URL) tools.blackbox.BURP_BRIDGE_URL = env.BURP_BRIDGE_URL;
  if (env.BURP_BRIDGE_TOKEN) tools.blackbox.BURP_BRIDGE_TOKEN = env.BURP_BRIDGE_TOKEN;
  writeFileSync(toolsPath, stringify(tools), { mode: 0o600, flag: 'wx' });
} else if (process.env.ARL_URL || process.env.ARL_TOKEN) {
  const tools = parse(readFileSync(toolsPath, 'utf8'));
  tools.arl ||= {};
  if (process.env.ARL_URL) tools.arl.ARL_URL = process.env.ARL_URL;
  if (process.env.ARL_TOKEN) tools.arl.ARL_TOKEN = process.env.ARL_TOKEN;
  writeFileSync(toolsPath, stringify(tools), { mode: 0o600 });
}
