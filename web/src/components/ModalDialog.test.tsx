import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import ModalDialog from './ModalDialog';

describe('ModalDialog', () => {
  it('renders nothing when open=false', () => {
    render(
      <ModalDialog open={false} title="Hidden" onClose={() => {}}>
        body content
      </ModalDialog>,
    );
    expect(screen.queryByText('Hidden')).toBeNull();
    expect(screen.queryByText('body content')).toBeNull();
  });

  it('renders title + children when open', () => {
    render(
      <ModalDialog open={true} title="Confirm thing" onClose={() => {}}>
        <p>This is the body</p>
      </ModalDialog>,
    );
    expect(screen.getByText('Confirm thing')).toBeInTheDocument();
    expect(screen.getByText('This is the body')).toBeInTheDocument();
  });

  it('Headless UI sets role=dialog + aria-modal on the panel', () => {
    render(
      <ModalDialog open={true} title="t" onClose={() => {}}>
        <span>body</span>
      </ModalDialog>,
    );
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
  });

  it('title acts as aria-labelledby target', () => {
    render(
      <ModalDialog open={true} title="Pin me" onClose={() => {}}>
        <span>body</span>
      </ModalDialog>,
    );
    const dialog = screen.getByRole('dialog');
    const labelId = dialog.getAttribute('aria-labelledby');
    expect(labelId).toBeTruthy();
    const labelEl = document.getElementById(labelId!);
    expect(labelEl).toHaveTextContent('Pin me');
  });

  it('ESC key fires onClose', () => {
    const onClose = vi.fn();
    render(
      <ModalDialog open={true} title="x" onClose={onClose}>
        <span>body</span>
      </ModalDialog>,
    );
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalled();
  });

  it('footer renders separately when provided', () => {
    render(
      <ModalDialog
        open={true}
        title="x"
        onClose={() => {}}
        footer={<button>OK</button>}
      >
        body
      </ModalDialog>,
    );
    expect(screen.getByRole('button', { name: 'OK' })).toBeInTheDocument();
  });
});
