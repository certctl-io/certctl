// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Breadcrumbs tests — Phase 3 UX-M5 closure.
// Verifies the useLocation()-driven segment-walker:
//   (a) root path "/" → no crumbs rendered (no empty <nav>)
//   (b) top-level paths → Home + that page
//   (c) detail paths → Home + List + Detail
//   (d) deeply-nested /issuers/:id/hierarchy → Home + Issuers + Detail + Hierarchy
//   (e) /auth/ subtree → uses authSubsegmentLabels
//   (f) terminal crumb has aria-current="page" and is plain text;
//       intermediate crumbs are <Link>s

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Breadcrumbs from './Breadcrumbs';

function renderAt(pathname: string) {
  return render(
    <MemoryRouter initialEntries={[pathname]}>
      <Breadcrumbs />
    </MemoryRouter>,
  );
}

describe('Breadcrumbs', () => {
  it('renders nothing for the dashboard root', () => {
    const { container } = renderAt('/');
    expect(container.querySelector('nav')).toBeNull();
  });

  it('renders Home + Certificates for /certificates', () => {
    renderAt('/certificates');
    expect(screen.getByText('Home')).toBeInTheDocument();
    expect(screen.getByText('Certificates')).toBeInTheDocument();
    const items = document.querySelectorAll('nav[aria-label="Breadcrumb"] ol > li');
    expect(items.length).toBe(2);
  });

  it('renders Home + Certificates + Detail for /certificates/cert-001', () => {
    renderAt('/certificates/cert-001');
    expect(screen.getByText('Home')).toBeInTheDocument();
    expect(screen.getByText('Certificates')).toBeInTheDocument();
    expect(screen.getByText('Detail')).toBeInTheDocument();
  });

  it('walks /issuers/:id/hierarchy down to the Hierarchy leaf', () => {
    renderAt('/issuers/iss-vault/hierarchy');
    expect(screen.getByText('Home')).toBeInTheDocument();
    expect(screen.getByText('Issuers')).toBeInTheDocument();
    expect(screen.getByText('Detail')).toBeInTheDocument();
    expect(screen.getByText('Hierarchy')).toBeInTheDocument();
    // Hierarchy is the terminal crumb — plain text, aria-current.
    const hierarchy = screen.getByText('Hierarchy');
    expect(hierarchy.tagName).toBe('SPAN');
    expect(hierarchy).toHaveAttribute('aria-current', 'page');
  });

  it('uses authSubsegmentLabels for /auth/* paths', () => {
    renderAt('/auth/oidc/providers');
    expect(screen.getByText('Access')).toBeInTheDocument();
    expect(screen.getByText('OIDC')).toBeInTheDocument();
    expect(screen.getByText('Providers')).toBeInTheDocument();
  });

  it("renders the last crumb as aria-current='page' plain text", () => {
    renderAt('/certificates/cert-001');
    const detail = screen.getByText('Detail');
    expect(detail.tagName).toBe('SPAN');
    expect(detail).toHaveAttribute('aria-current', 'page');
  });

  it('renders intermediate crumbs as <Link> elements pointing at their pathname', () => {
    renderAt('/certificates/cert-001');
    const home = screen.getByText('Home');
    const homeAnchor = home.closest('a');
    expect(homeAnchor).not.toBeNull();
    expect(homeAnchor!.getAttribute('href')).toBe('/');

    const certs = screen.getByText('Certificates');
    const certsAnchor = certs.closest('a');
    expect(certsAnchor).not.toBeNull();
    expect(certsAnchor!.getAttribute('href')).toBe('/certificates');
  });

  it('exposes nav[aria-label="Breadcrumb"] for screen readers', () => {
    renderAt('/issuers');
    expect(
      screen.getByRole('navigation', { name: 'Breadcrumb' }),
    ).toBeInTheDocument();
  });
});
