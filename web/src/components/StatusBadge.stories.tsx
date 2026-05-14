// Phase 8 TEST-H3 closure — StatusBadge stories.
// One story per wire-enum value is the source-of-truth: if the server
// returns a new status, the gap shows up as a missing story.

import type { Meta, StoryObj } from '@storybook/react';
import StatusBadge from './StatusBadge';

const meta = {
  title: 'Primitives/StatusBadge',
  component: StatusBadge,
  tags: ['autodocs'],
  argTypes: {
    status: { control: 'text' },
  },
} satisfies Meta<typeof StatusBadge>;

export default meta;
type Story = StoryObj<typeof meta>;

// Phase 1 UX-H5 closure: 25 known wire values (verified live count
// from src/components/StatusBadge.test.tsx). Each one is a story so
// the swatch book shows every variant the server can emit.
export const Active: Story = { args: { status: 'Active' } };
export const Expiring: Story = { args: { status: 'Expiring' } };
export const Expired: Story = { args: { status: 'Expired' } };
export const Revoked: Story = { args: { status: 'Revoked' } };
export const Pending: Story = { args: { status: 'Pending' } };
export const RenewalInProgress: Story = { args: { status: 'RenewalInProgress' } };
export const Failed: Story = { args: { status: 'Failed' } };
export const AwaitingApproval: Story = { args: { status: 'AwaitingApproval' } };
export const AwaitingCSR: Story = { args: { status: 'AwaitingCSR' } };
export const Archived: Story = { args: { status: 'Archived' } };

// Unknown status → falls through to the titleCase fallback (Phase 1).
// Pinning this ensures a new server-side enum value doesn't render
// as a blank chip.
export const UnknownFallback: Story = { args: { status: 'CompletelyMadeUpStatus' } };
