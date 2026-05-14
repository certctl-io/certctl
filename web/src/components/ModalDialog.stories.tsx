// Phase 8 TEST-H3 — ModalDialog stories. Renders open by default so
// the showroom shows the focus-trapped panel + the role=dialog +
// aria-modal semantics the FE-H3 closure (Phase 5) shipped.

import type { Meta, StoryObj } from '@storybook/react';
import ModalDialog from './ModalDialog';

const meta = {
  title: 'Primitives/ModalDialog',
  component: ModalDialog,
  tags: ['autodocs'],
  args: { open: true, onClose: () => {} },
} satisfies Meta<typeof ModalDialog>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Simple: Story = {
  args: {
    title: 'Reload trust anchor',
    children: 'This re-reads the trust anchor file and atomically swaps the trust pool.',
  },
};

export const WithFooter: Story = {
  args: {
    title: 'Confirm action',
    children: <p>This action is reversible — proceed?</p>,
    footer: (
      <>
        <button className="btn btn-ghost">Cancel</button>
        <button className="btn btn-primary">Confirm</button>
      </>
    ),
  },
};

export const LargeMaxWidth: Story = {
  args: {
    title: 'Retire agent',
    maxWidth: 'lg',
    children: <p>Soft-retire the agent. Reversible only via direct DB intervention.</p>,
  },
};
