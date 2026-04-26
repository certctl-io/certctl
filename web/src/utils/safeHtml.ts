// Bundle-8 / Audit L-019 / CWE-79 (XSS):
//
// Single chokepoint for any code that needs `dangerouslySetInnerHTML`.
// At Bundle-8 time the codebase has ZERO `dangerouslySetInnerHTML` sites
// (verified via `grep -rn dangerouslySetInnerHTML web/src/`); this file
// is preventive — when a future feature genuinely needs to render a
// trusted-but-rich HTML fragment (markdown email body, signed
// notification template, etc.) it MUST route through `sanitizeHtml`
// instead of inlining the dangerous attribute.
//
// The CI regression guard at `.github/workflows/ci.yml` blocks any new
// bare `dangerouslySetInnerHTML` from landing — see the
// "Bundle-8 / L-019 dangerouslySetInnerHTML guard" step.
//
// We don't take a runtime DOMPurify dependency in Bundle-8 because the
// allowlist is empty at HEAD. When the first real call site lands, add
// `dompurify` to package.json and replace the body of `sanitizeHtml`
// with a real DOMPurify call. Until then this file documents the
// contract and provides a typed boundary the linter can recognise.

/**
 * Sanitize an arbitrary HTML string before passing it to React's
 * `dangerouslySetInnerHTML` prop. Bundle-8 placeholder — see the file
 * doc comment above for the activation procedure when the first real
 * call site lands.
 *
 * @param html - the untrusted HTML payload
 * @param _options - reserved for the future DOMPurify config object
 * @returns the sanitized string ready to assign to `__html`
 */
export function sanitizeHtml(html: string, _options?: SanitizeOptions): string {
  if (!html) return '';
  // Bundle-8: until the first real call site lands, refuse to render
  // anything. Throwing here is the safe default — a future regression
  // that imports this helper without enabling DOMPurify will fail loud
  // at runtime (test) instead of silently rendering attacker HTML.
  throw new Error(
    'safeHtml.sanitizeHtml is a placeholder. Add dompurify to package.json ' +
      'and implement the body before using this helper. See ' +
      'web/src/utils/safeHtml.ts file header for the contract.',
  );
}

/**
 * Reserved for the DOMPurify configuration object that the future real
 * implementation will accept. Documented now so call-site signatures
 * don't change when the body lights up.
 */
export interface SanitizeOptions {
  /** Tags that should survive sanitization (default: `['b','i','em','strong','a','p','br']`) */
  allowedTags?: string[];
  /** Attributes that should survive sanitization (default: `['href','title']`) */
  allowedAttr?: string[];
}
