// Bundle-8 / Audit M-010:
// regression coverage for useListParams. Exercises the URL contract
// (page/page_size/sort/filter[*]), default omission (defaults stay out
// of the URL), filter-resets-page invariant, and resetParams.

import { describe, it, expect } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { MemoryRouter, useSearchParams } from 'react-router-dom';
import { useListParams } from './useListParams';
import type { ReactNode } from 'react';

function wrapper(initialEntries: string[]) {
  return ({ children }: { children: ReactNode }) => (
    <MemoryRouter initialEntries={initialEntries}>{children}</MemoryRouter>
  );
}

describe('useListParams — Bundle-8 / M-010', () => {
  it('reads defaults when URL is empty', () => {
    const { result } = renderHook(() => useListParams(), { wrapper: wrapper(['/']) });
    expect(result.current.params.page).toBe(1);
    expect(result.current.params.pageSize).toBe(25);
    expect(result.current.params.sort).toBe('');
    expect(result.current.params.filters).toEqual({});
  });

  it('parses page/page_size/sort/filter[*] from the URL', () => {
    const { result } = renderHook(() => useListParams(), {
      wrapper: wrapper(['/?page=3&page_size=50&sort=-created_at&filter[status]=active&filter[team_id]=t-platform']),
    });
    expect(result.current.params.page).toBe(3);
    expect(result.current.params.pageSize).toBe(50);
    expect(result.current.params.sort).toBe('-created_at');
    expect(result.current.params.filters).toEqual({
      status: 'active',
      team_id: 't-platform',
    });
  });

  it('honours per-call defaults overrides', () => {
    const { result } = renderHook(
      () => useListParams({ pageSize: 100, sort: 'name' }),
      { wrapper: wrapper(['/']) },
    );
    expect(result.current.params.pageSize).toBe(100);
    expect(result.current.params.sort).toBe('name');
  });

  it('rejects garbage page values and falls back to default', () => {
    const { result } = renderHook(() => useListParams(), {
      wrapper: wrapper(['/?page=not-a-number&page_size=-5']),
    });
    expect(result.current.params.page).toBe(1);
    expect(result.current.params.pageSize).toBe(25);
  });

  it('omits defaults from the URL on update', () => {
    function Hookrunner() {
      const [params] = useSearchParams();
      const list = useListParams();
      return { params, list };
    }
    const { result } = renderHook(() => Hookrunner(), { wrapper: wrapper(['/']) });

    act(() => result.current.list.setPage(2));
    expect(result.current.params.get('page')).toBe('2');
    act(() => result.current.list.setPage(1));
    expect(result.current.params.get('page')).toBeNull(); // default omitted
  });

  it('filter changes reset page to 1', () => {
    function Hookrunner() {
      const [params] = useSearchParams();
      const list = useListParams();
      return { params, list };
    }
    const { result } = renderHook(() => Hookrunner(), { wrapper: wrapper(['/?page=5']) });
    expect(result.current.params.get('page')).toBe('5');
    act(() => result.current.list.setFilter('status', 'active'));
    // page key removed because the setter resets pagination on filter change
    expect(result.current.params.get('page')).toBeNull();
    expect(result.current.params.get('filter[status]')).toBe('active');
  });

  it('resetParams clears every search param', () => {
    function Hookrunner() {
      const [params] = useSearchParams();
      const list = useListParams();
      return { params, list };
    }
    const { result } = renderHook(() => Hookrunner(), {
      wrapper: wrapper(['/?page=2&filter[status]=active']),
    });
    act(() => result.current.list.resetParams());
    expect(Array.from(result.current.params.keys())).toEqual([]);
  });
});
