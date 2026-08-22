'use strict';

const fs = require('fs');
const path = require('path');

class SecurityDenial extends Error {}

function normalizeVirtualPath(value) {
  if (typeof value !== 'string' || !value.trim()) throw new SecurityDenial('empty path');
  const p = value.replaceAll('\\', '/');

  if (/^[A-Za-z]:/.test(p)) throw new SecurityDenial('Windows absolute path denied');
  if (p.startsWith('//')) throw new SecurityDenial('UNC path denied');
  if (p.startsWith('/')) throw new SecurityDenial('absolute path denied');
  if (p.startsWith('~')) throw new SecurityDenial('home expansion denied');
  if (p.split('/').includes('..')) throw new SecurityDenial('parent traversal denied');

  return p.replace(/^\.\/+/, '');
}

function underScope(rel, scopes) {
  rel = normalizeVirtualPath(rel);
  return (scopes || []).some(scope => {
    const s = normalizeVirtualPath(scope).replace(/\/+$/, '');
    return rel === s || rel.startsWith(s + '/');
  });
}

class GuardedCodingTools {
  constructor(root, packet) {
    this.root = path.resolve(root);
    this.packet = packet || {};
    this.modified = new Set();
  }

  real(rel) {
    rel = normalizeVirtualPath(rel);
    const resolved = path.resolve(this.root, rel);

    if (resolved !== this.root && !resolved.startsWith(this.root + path.sep)) {
      throw new SecurityDenial('workspace escape denied');
    }

    // Existing ancestor realpath check: blocks symlink/junction escape.
    const parts = rel.split('/').filter(Boolean);
    let cursor = this.root;
    for (const part of parts) {
      cursor = path.join(cursor, part);
      if (fs.existsSync(cursor)) {
        const real = fs.realpathSync(cursor);
        if (real !== this.root && !real.startsWith(this.root + path.sep)) {
          throw new SecurityDenial('symlink/junction escape denied');
        }
      }
    }

    return resolved;
  }

  read(rel) {
    const scopes = [
      ...(this.packet.context_files || []),
      ...(this.packet.allowed_files || [])
    ];
    if (!underScope(rel, scopes)) throw new SecurityDenial(`read denied: ${rel}`);
    return fs.readFileSync(this.real(rel), 'utf8');
  }

  grep(term, files) {
    const results = [];
    for (const file of files || []) {
      try {
        const text = this.read(file);
        text.split(/\r?\n/).forEach((line, i) => {
          if (line.includes(term)) results.push({ file, line: i + 1, text: line });
        });
      } catch (e) {
        if (!(e instanceof SecurityDenial)) throw e;
      }
    }
    return results;
  }

  editExact(rel, before, after) {
    if (!underScope(rel, this.packet.allowed_files || [])) {
      throw new SecurityDenial(`write denied: ${rel}`);
    }

    const p = this.real(rel);
    const text = fs.readFileSync(p, 'utf8');
    const hits = text.split(before).length - 1;
    if (hits !== 1) throw new Error(`exact edit requires one match; got ${hits}`);

    fs.writeFileSync(p, text.replace(before, after), 'utf8');
    this.modified.add(normalizeVirtualPath(rel));
    return { file: normalizeVirtualPath(rel), changed: true };
  }
}

module.exports = {
  GuardedCodingTools,
  SecurityDenial,
  normalizeVirtualPath,
  underScope
};
