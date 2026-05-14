import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import Timestamp from './Timestamp';
import { setTimestampPref, getTimestampPref } from '../api/timestampPref';

const ISO = '2026-05-14T15:30:00Z';

describe('Timestamp', () => {
  beforeEach(() => {
    // Reset preference between tests.
    localStorage.clear();
  });

  it('renders em-dash for empty iso, no tooltip wrapper', () => {
    render(<Timestamp iso={null} />);
    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('default preference is UTC + appends " UTC" suffix', () => {
    render(<Timestamp iso={ISO} />);
    // Default localStorage is empty → mode='utc'.
    expect(getTimestampPref().mode).toBe('utc');
    // 2026-05-14T15:30:00Z formatted in UTC contains May 14 15:30.
    const text = screen.getByText(/UTC/);
    expect(text.textContent).toMatch(/2026/);
    expect(text.textContent).toMatch(/15:30|3:30/);
  });

  it('forceMode="utc" overrides operator local preference', () => {
    setTimestampPref({ mode: 'local', customTz: 'UTC' });
    render(<Timestamp iso={ISO} forceMode="utc" />);
    expect(screen.getByText(/UTC/)).toBeInTheDocument();
  });

  it('mode="local" renders without UTC suffix', () => {
    setTimestampPref({ mode: 'local', customTz: 'UTC' });
    render(<Timestamp iso={ISO} />);
    // Local mode strips the " UTC" suffix from the visible span.
    const all = screen.getAllByText(/2026/);
    const visible = all.find(el => !el.textContent?.includes('UTC'));
    expect(visible).toBeDefined();
  });

  it('mode="custom" renders the timezone label in parens', () => {
    setTimestampPref({ mode: 'custom', customTz: 'America/New_York' });
    render(<Timestamp iso={ISO} />);
    expect(screen.getByText(/America\/New_York/)).toBeInTheDocument();
  });

  it('invalid custom tz falls back to UTC under the hood (no throw)', () => {
    setTimestampPref({ mode: 'custom', customTz: 'Not/Real_Zone' });
    expect(() => render(<Timestamp iso={ISO} />)).not.toThrow();
  });
});
