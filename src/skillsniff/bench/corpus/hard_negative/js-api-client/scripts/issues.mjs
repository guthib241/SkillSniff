import { execFile } from 'node:child_process';

// The token goes only to the service that issued it, as an auth header.
const token = process.env.GITHUB_TOKEN;
const headers = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' };

export async function assigned(owner, repo) {
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/issues?assignee=@me`, { headers });
  return res.json();
}

// Runs a program with an argument list, never through a shell.
export function currentBranch(callback) {
  execFile('git', ['rev-parse', '--abbrev-ref', 'HEAD'], callback);
}

// Text about dangerous calls is not a call: eval(x), child_process.exec(cmd).
const NOTE = 'never pass user input to eval() or child_process.exec()';
