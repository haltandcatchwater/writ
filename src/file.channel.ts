/**
 * Writ — File Channel. Scoped to allowed directories and operations.
 *
 * A file channel scoped to "./output/" only writes there.
 * The agent can't widen the scope because it can't touch channel code.
 *
 * Supports read/write/list and the destructive primitives delete/rename/mkdir/rmdir.
 * `protectedPaths` is a deny-list that overrides `allowedPaths` — even if a path
 * is under an allowed directory, it is rejected if it falls under any protected
 * path. This allows broad allowed-paths grants with non-negotiable safety carve-outs
 * (.git/, .env, secrets/) the agent can never reach.
 */

import {
  existsSync, readFileSync, writeFileSync, readdirSync,
  unlinkSync, renameSync, mkdirSync, rmdirSync,
  statSync, realpathSync,
} from "fs";
import { resolve, relative, normalize, extname, dirname, basename } from "path";
import { createHash } from "crypto";
import { ScopedChannel } from "./base-channel";
import type { FileScope, FileOperation, ChannelResult } from "./types";

export interface FileIntent {
  operation: FileOperation;
  /** For most operations, the target path. For `rename`, this is the source path. */
  path: string;
  /** Required for `write`. */
  content?: string;
  /** Required for `rename`: destination path. */
  to?: string;
  /**
   * For `read`: when true, response includes `sha256` of the file's bytes
   * alongside `data`. Used by hash-pinned workflows where downstream steps
   * need to detect filesystem drift.
   */
  withHash?: boolean;
}

export class FileChannel extends ScopedChannel<FileScope> {
  /** Counter for delete + rmdir operations against the maxDeletesPerRun cap. */
  private deleteCounter = 0;

  constructor(name: string, scope: FileScope) {
    super(name, scope);
  }

  /**
   * Canonicalize a path, following symlinks. For paths that don't exist yet
   * (write/create/mkdir targets), canonicalize the parent and append the
   * basename — that catches the case where the parent itself is a symlink.
   * If neither the path nor its parent exists, fall back to the lexical
   * resolved path; the operation will fail at execute() time with ENOENT
   * regardless, no symlink danger.
   */
  private canonicalize(targetPath: string): string {
    const lex = resolve(targetPath);
    try {
      if (existsSync(lex)) {
        return realpathSync(lex);
      }
      const parent = dirname(lex);
      if (existsSync(parent)) {
        return resolve(realpathSync(parent), basename(lex));
      }
      return lex;
    } catch {
      // realpathSync threw — return lex; downstream check will fail closed.
      return lex;
    }
  }

  /**
   * True if `targetPath` is under any allowed directory and not under any
   * protected directory, AFTER canonicalization (symlinks resolved). Without
   * canonicalization, an attacker could plant a symlink inside the workspace
   * pointing to /etc/shadow, and the lexical scope check would approve it
   * — execute() would then follow the symlink and write outside the sandbox.
   */
  private isPathAllowed(targetPath: string): boolean {
    const resolved = this.canonicalize(targetPath);

    const underAllowed = this.scope.allowedPaths.some((allowed) => {
      const allowedResolved = this.canonicalize(allowed);
      const rel = relative(allowedResolved, resolved);
      return !rel.startsWith("..") && !resolve(allowedResolved, rel).includes("..");
    });

    if (!underAllowed) return false;

    // Deny overrides allow: even if under allowedPaths, reject if under any protectedPath.
    // `relative(A, B)` returns "" if A==B, "../..." if B is outside A, "subdir/..." if B is inside A.
    if (this.scope.protectedPaths && this.scope.protectedPaths.length > 0) {
      const underProtected = this.scope.protectedPaths.some((protectedPath) => {
        const protectedResolved = this.canonicalize(protectedPath);
        const rel = relative(protectedResolved, resolved);
        // "" means target equals protected; non-".." means target is inside protected.
        return rel === "" || (!rel.startsWith("..") && !rel.startsWith("/") && !/^[A-Za-z]:/.test(rel));
      });
      if (underProtected) return false;
    }

    return true;
  }

  /** True if `targetPath`'s extension is in the protected-extensions deny-list. */
  private isExtensionProtected(targetPath: string): boolean {
    if (!this.scope.protectedExtensions || this.scope.protectedExtensions.length === 0) {
      return false;
    }
    const base = targetPath.split(/[\\/]/).pop() ?? "";
    const ext = extname(base);
    // Match either the basename (e.g., "package-lock.json") or just the extension (e.g., ".snap")
    return this.scope.protectedExtensions.some((protectedExt) => {
      if (protectedExt.startsWith(".")) return ext === protectedExt;
      return base === protectedExt;
    });
  }

  validateIntent(intent: unknown): string | null {
    const req = intent as FileIntent;

    if (!req || typeof req !== "object") {
      return "Intent must be a FileIntent object";
    }

    if (!req.operation) {
      return "Intent must include an operation";
    }

    if (!this.scope.allowedOperations.includes(req.operation)) {
      return `Operation "${req.operation}" is not allowed. Allowed: ${this.scope.allowedOperations.join(", ")}`;
    }

    if (!req.path || typeof req.path !== "string") {
      return "Intent must include a path string";
    }

    // Normalize to prevent traversal attacks
    const normalized = normalize(req.path);
    if (normalized.includes("..")) {
      return "Path traversal (..) is not allowed";
    }

    if (!this.isPathAllowed(req.path)) {
      return `Path "${req.path}" is outside allowed directories or under a protected path`;
    }

    // For rename, validate BOTH endpoints — atomicity must be structurally safe.
    if (req.operation === "rename") {
      if (!req.to || typeof req.to !== "string") {
        return "Rename operation requires a 'to' destination path";
      }
      const normalizedTo = normalize(req.to);
      if (normalizedTo.includes("..")) {
        return "Destination path traversal (..) is not allowed";
      }
      if (!this.isPathAllowed(req.to)) {
        return `Destination "${req.to}" is outside allowed directories or under a protected path`;
      }
      if (this.isExtensionProtected(req.to)) {
        return `Destination "${req.to}" has a protected extension`;
      }
    }

    if (req.operation === "write") {
      if (req.content === undefined) {
        return "Write operation requires content";
      }
      if (this.isExtensionProtected(req.path)) {
        return `Path "${req.path}" has a protected extension (e.g., lockfile)`;
      }
      if (this.scope.maxFileSize !== undefined) {
        const size = Buffer.byteLength(req.content, "utf-8");
        if (size > this.scope.maxFileSize) {
          return `Write size ${size} bytes exceeds maxFileSize ${this.scope.maxFileSize}`;
        }
      }
    }

    if (req.operation === "delete" || req.operation === "rmdir") {
      const cap = this.scope.maxDeletesPerRun;
      if (cap !== undefined && this.deleteCounter >= cap) {
        return `Delete cap exceeded (maxDeletesPerRun=${cap}); refusing further destructive operations`;
      }
    }

    return null;
  }

  async execute(intent: unknown): Promise<ChannelResult> {
    const req = intent as FileIntent;

    try {
      switch (req.operation) {
        case "read": {
          if (!existsSync(req.path)) {
            return { success: false, error: `File not found: ${req.path}` };
          }
          if (req.withHash) {
            // Read bytes for hashing, then decode for the data field.
            const bytes = readFileSync(req.path);
            const sha256 = createHash("sha256").update(bytes).digest("hex");
            const data = bytes.toString("utf-8");
            return { success: true, data: { content: data, sha256 } } as ChannelResult;
          }
          const data = readFileSync(req.path, "utf-8");
          return { success: true, data };
        }

        case "write": {
          writeFileSync(req.path, req.content!, "utf-8");
          return { success: true };
        }

        case "list": {
          if (!existsSync(req.path)) {
            return { success: false, error: `Directory not found: ${req.path}` };
          }
          const entries = readdirSync(req.path);
          return { success: true, data: entries };
        }

        case "delete": {
          if (!existsSync(req.path)) {
            return { success: false, error: `File not found: ${req.path}` };
          }
          const stat = statSync(req.path);
          if (stat.isDirectory()) {
            return { success: false, error: `Path is a directory; use rmdir: ${req.path}` };
          }
          unlinkSync(req.path);
          this.deleteCounter += 1;
          return { success: true };
        }

        case "rename": {
          if (!existsSync(req.path)) {
            return { success: false, error: `Source not found: ${req.path}` };
          }
          renameSync(req.path, req.to!);
          return { success: true };
        }

        case "mkdir": {
          mkdirSync(req.path, { recursive: true });
          return { success: true };
        }

        case "rmdir": {
          if (!existsSync(req.path)) {
            return { success: false, error: `Directory not found: ${req.path}` };
          }
          const stat = statSync(req.path);
          if (!stat.isDirectory()) {
            return { success: false, error: `Path is not a directory: ${req.path}` };
          }
          // Non-recursive: only empty directories. Recursive bulk-rmdir requires explicit
          // multi-call orchestration through delete + rmdir, each counting against cap.
          rmdirSync(req.path);
          this.deleteCounter += 1;
          return { success: true };
        }

        default:
          return { success: false, error: `Unknown operation: ${(req as FileIntent).operation}` };
      }
    } catch (err) {
      return {
        success: false,
        error: `File operation failed: ${(err as Error).message}`,
      };
    }
  }
}
