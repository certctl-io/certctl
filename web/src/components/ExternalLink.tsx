// Bundle-8 / Audit L-015 / CWE-1022 (Use of Web Link to Untrusted Target
// with window.opener Access) / Reverse-tabnabbing:
//
// Single chokepoint for any anchor that opens in a new tab. Forces the
// `rel="noopener noreferrer"` pair so a malicious page at the target URL
// cannot navigate the opener window via `window.opener.location =
// 'https://evil.example/'`.
//
// At Bundle-8 time the codebase has 3 `target="_blank"` sites (all in
// OnboardingWizard.tsx, all already correct). This component exists so
// future external-link additions route through one path and the CI
// regression guard at `.github/workflows/ci.yml` ("Bundle-8 / L-015
// target=_blank guard") can grep-fail any new bare `target="_blank"`
// outside this component.
//
// Usage:
//
//   <ExternalLink href="https://docs.example.com/setup">Setup guide</ExternalLink>
//
// The component renders the same `<a>` element + className conventions
// as the existing OnboardingWizard sites so retrofits are mechanical.

import type { AnchorHTMLAttributes, ReactNode } from 'react';

interface ExternalLinkProps
  extends Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'rel' | 'target'> {
  /** The external URL to open in a new tab. Required. */
  href: string;
  /** Anchor body. Typically the link text. */
  children: ReactNode;
}

export function ExternalLink({ href, children, className, ...rest }: ExternalLinkProps) {
  return (
    <a
      {...rest}
      href={href}
      target="_blank"
      // Bundle-8 / L-015: NEVER drop the rel value. The CI regression
      // guard greps for any `target="_blank"` outside this component
      // and fails the build if it finds one without `noopener`.
      rel="noopener noreferrer"
      className={className}
    >
      {children}
    </a>
  );
}
