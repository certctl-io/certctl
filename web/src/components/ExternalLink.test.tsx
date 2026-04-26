// Bundle-8 / Audit L-015 / CWE-1022:
// regression coverage for the ExternalLink component. Confirms the
// rel="noopener noreferrer" pair is hardcoded and the forwarded
// attributes survive — defends against a future "I'll just spread the
// rest props" refactor that accidentally lets the caller override `rel`.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ExternalLink } from './ExternalLink';

describe('ExternalLink — Bundle-8 / L-015', () => {
  it('renders target=_blank with rel=noopener noreferrer', () => {
    render(
      <ExternalLink href="https://docs.example.com/setup">Setup guide</ExternalLink>,
    );
    const link = screen.getByRole('link', { name: 'Setup guide' });
    expect(link.getAttribute('target')).toBe('_blank');
    expect(link.getAttribute('rel')).toBe('noopener noreferrer');
    expect(link.getAttribute('href')).toBe('https://docs.example.com/setup');
  });

  it('preserves caller className without dropping rel', () => {
    render(
      <ExternalLink href="https://example.com" className="text-accent">
        Link
      </ExternalLink>,
    );
    const link = screen.getByRole('link', { name: 'Link' });
    expect(link.className).toBe('text-accent');
    expect(link.getAttribute('rel')).toBe('noopener noreferrer');
  });
});
