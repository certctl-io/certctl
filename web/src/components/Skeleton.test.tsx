import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import Skeleton from './Skeleton';

describe('Skeleton', () => {
  it('page variant renders PageHeader-shaped band + 4 stat tiles + card', () => {
    const { container, getByRole } = render(<Skeleton variant="page" />);
    expect(getByRole('status')).toHaveAttribute('aria-busy', 'true');
    expect(getByRole('status')).toHaveAttribute('aria-label', 'Loading content');
    expect(container.querySelector('.animate-pulse')).not.toBeNull();
    // 4 stat tiles
    expect(container.querySelectorAll('.grid > .bg-surface')).toHaveLength(4);
  });

  it('table variant defaults to 6 rows × 5 cols', () => {
    const { container } = render(<Skeleton variant="table" />);
    const rows = container.querySelectorAll('tbody tr');
    expect(rows).toHaveLength(6);
    const cells = rows[0].querySelectorAll('td');
    expect(cells).toHaveLength(5);
  });

  it('table variant respects custom rows + columns', () => {
    const { container } = render(<Skeleton variant="table" rows={3} columns={4} />);
    expect(container.querySelectorAll('tbody tr')).toHaveLength(3);
    expect(container.querySelectorAll('tbody tr:first-child td')).toHaveLength(4);
  });

  it('card variant renders title-row + 3 prose rows', () => {
    const { container } = render(<Skeleton variant="card" />);
    // 1 title + 3 prose lines = 4 stripes inside the inner card
    const stripes = container.querySelectorAll('.bg-surface > div, .bg-surface .space-y-2 > div');
    expect(stripes.length).toBeGreaterThanOrEqual(4);
  });

  it('stat variant renders label-row + number-row', () => {
    const { container, getByRole } = render(<Skeleton variant="stat" />);
    expect(getByRole('status')).toHaveAttribute('aria-busy', 'true');
    // 2 stripes
    expect(container.querySelectorAll('.bg-surface-border')).toHaveLength(2);
  });

  it('custom ariaLabel surfaces on the role=status root', () => {
    const { getByRole } = render(
      <Skeleton variant="card" ariaLabel="Loading certificates" />,
    );
    expect(getByRole('status')).toHaveAttribute('aria-label', 'Loading certificates');
  });
});
