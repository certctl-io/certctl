// Phase 8 TEST-H3 — Skeleton stories. The 4 variants each get a story
// so the showroom exposes the full shape catalog. animate-pulse is
// visible in the rendered story.

import type { Meta, StoryObj } from '@storybook/react';
import Skeleton from './Skeleton';

const meta = {
  title: 'Primitives/Skeleton',
  component: Skeleton,
  tags: ['autodocs'],
} satisfies Meta<typeof Skeleton>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Page: Story = { args: { variant: 'page' } };
export const Table: Story = { args: { variant: 'table' } };
export const Card: Story = { args: { variant: 'card' } };
export const Stat: Story = { args: { variant: 'stat' } };

export const TableCustomColumns: Story = {
  args: { variant: 'table', rows: 3, columns: 7 },
};
