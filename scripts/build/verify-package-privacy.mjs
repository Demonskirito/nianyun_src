// Keep a private repository from publishing a public GHCR package.
// A public repository must not leave the package private after a release,
// or anonymous compose pulls will fail.
const token = process.env.GH_TOKEN;
const repository = process.env.GITHUB_REPOSITORY;
if (!token || !repository) throw new Error('GH_TOKEN and GITHUB_REPOSITORY are required');
async function get(path, allowMissing = false) {
  const response = await fetch(`https://api.github.com/${path}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
  });
  if (response.status === 404 && allowMissing) return null;
  if (!response.ok) throw new Error(`GitHub API ${path}: HTTP ${response.status}`);
  return response.json();
}
const repo = await get(`repos/${repository}`);
const owner = repo.owner;
const path = `${owner.type === 'Organization' ? 'orgs' : 'users'}/${owner.login}/packages/container/nianyun`;
const requireExisting = process.argv.includes('--require-existing');
const pkg = await get(path, !requireExisting);
if (repo.private) {
  if (pkg && pkg.visibility !== 'private') throw new Error(`Refusing release: private repository cannot publish a ${pkg.visibility} package`);
  console.log(pkg ? 'Verified: repository and package are private.' : 'Private repository; new GHCR package will default to private.');
} else if (requireExisting && pkg && pkg.visibility === 'private') {
  throw new Error('Public repository published a private GHCR package; anonymous pull will fail. Set the package visibility to Public.');
} else {
  console.log(pkg ? `Repository is public; package visibility is ${pkg.visibility || 'unknown'}.` : 'Repository is public; package not created yet.');
}
