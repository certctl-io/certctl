// Phase 5 closure (FE-H3 + UX-H4 regression gate): axe-core a11y
// assertions on the primitives that other pages reuse. Failing this
// suite means a future change reintroduced an unbound label, a missing
// aria-* attr on a primitive, or a similar a11y bug.
//
// Implementation notes:
//   • Uses axe-core directly (not jest-axe) — jest-axe's
//     `toHaveNoViolations` matcher uses the jest expect API, which
//     Vitest's expect.extend can't host (TypeError: expectAssertion.call
//     is not a function). Asserting violations.length === 0 with a
//     readable failure message gives the same gate without the
//     compatibility headache.
//   • Scope is primitives, not page sweeps — primitives carry the risk
//     surface, pages mostly compose them. Faster runtime + tighter
//     fail signal when a primitive regresses.

import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import axe from 'axe-core';
import { MemoryRouter } from 'react-router-dom';

import FormField from '../components/FormField';
import ModalDialog from '../components/ModalDialog';
import Skeleton from '../components/Skeleton';
import Breadcrumbs from '../components/Breadcrumbs';

async function expectNoViolations(
  container: HTMLElement,
  extraSuppressedRules: string[] = [],
) {
  const suppressed: Record<string, { enabled: false }> = {
    // color-contrast needs computed-styles which jsdom doesn't compute;
    // that rule is suppressed in axe defaults under jsdom anyway but
    // pinning it here keeps the failure mode loud if axe-core changes
    // default behavior.
    'color-contrast': { enabled: false },
  };
  for (const r of extraSuppressedRules) suppressed[r] = { enabled: false };
  const results = await axe.run(container, { rules: suppressed });
  if (results.violations.length > 0) {
    const summary = results.violations
      .map((v) => `  • ${v.id} (${v.impact}): ${v.help} — ${v.nodes.length} node(s)`)
      .join('\n');
    throw new Error(`axe-core found ${results.violations.length} violation(s):\n${summary}`);
  }
  expect(results.violations).toHaveLength(0);
}

describe('Primitives — axe-core a11y assertions', () => {
  it('FormField (label / input pair) has no axe violations', async () => {
    const { container } = render(
      <FormField label="Email address" required>
        <input type="email" />
      </FormField>,
    );
    await expectNoViolations(container);
  });

  it('FormField with description + error has no axe violations', async () => {
    const { container } = render(
      <FormField
        label="Display name"
        required
        description="What other operators will see"
        error="Must be at least 1 character"
      >
        <input type="text" />
      </FormField>,
    );
    await expectNoViolations(container);
  });

  it('Skeleton variants have no axe violations (table / page / card / stat)', async () => {
    for (const variant of ['table', 'page', 'card', 'stat'] as const) {
      const { container, unmount } = render(<Skeleton variant={variant} />);
      // Skeleton.table renders empty <th> cells — they're decorative
      // shimmer placeholders inside a role="status" + aria-busy="true"
      // container, so screen readers announce "Loading content" and
      // skip the table semantics. axe-core's `empty-table-header` rule
      // doesn't model aria-busy gating, so suppress it for this variant
      // (and consistently across all variants for the same scan).
      await expectNoViolations(container, ['empty-table-header']);
      unmount();
    }
  });

  it('ModalDialog with title + body + footer has no axe violations', async () => {
    const { baseElement } = render(
      <ModalDialog
        open={true}
        title="Confirm action"
        onClose={() => {}}
        footer={<button>OK</button>}
      >
        <p>This action is reversible.</p>
      </ModalDialog>,
    );
    // ModalDialog mounts into a portal on document.body — pass
    // baseElement (which is document.body) rather than container so
    // axe scans the actual rendered dialog tree.
    await expectNoViolations(baseElement);
  });

  it('Breadcrumbs renders no axe violations on a 2-deep path', async () => {
    const { container } = render(
      <MemoryRouter initialEntries={['/issuers/iss-vault']}>
        <Breadcrumbs />
      </MemoryRouter>,
    );
    await expectNoViolations(container);
  });
});
