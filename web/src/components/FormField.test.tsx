import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { useForm } from 'react-hook-form';
import FormField from './FormField';

describe('FormField', () => {
  it('label htmlFor matches input id (the WCAG 1.3.1 contract)', () => {
    render(
      <FormField label="Email">
        <input type="email" />
      </FormField>,
    );
    const label = screen.getByText('Email');
    const input = screen.getByLabelText('Email');
    // Programmatic label association — what screen readers use.
    expect(input).toBeInTheDocument();
    expect(label).toHaveAttribute('for', input.id);
    // useId() gives a non-empty id by definition.
    expect(input.id).toMatch(/^field-/);
  });

  it('two siblings get independent ids (no collision)', () => {
    render(
      <>
        <FormField label="Name"><input /></FormField>
        <FormField label="Description"><input /></FormField>
      </>,
    );
    const a = screen.getByLabelText('Name');
    const b = screen.getByLabelText('Description');
    expect(a.id).not.toBe(b.id);
  });

  it('required surfaces the asterisk + aria-required on the child', () => {
    render(
      <FormField label="Email" required>
        <input type="email" />
      </FormField>,
    );
    expect(screen.getByText('*')).toBeInTheDocument();
    expect(screen.getByLabelText(/Email/)).toHaveAttribute('aria-required', 'true');
  });

  it('description wires aria-describedby to the child', () => {
    render(
      <FormField label="Token" description="Paste the API key from /auth/keys">
        <input />
      </FormField>,
    );
    const input = screen.getByLabelText('Token');
    const desc = screen.getByText(/Paste the API key/);
    expect(input.getAttribute('aria-describedby')).toContain(desc.id);
  });

  it('error sets aria-invalid + role=alert + extends aria-describedby', () => {
    render(
      <FormField label="Email" error="Must be a valid email address">
        <input type="email" />
      </FormField>,
    );
    const input = screen.getByLabelText('Email');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    const err = screen.getByRole('alert');
    expect(err).toHaveTextContent('Must be a valid email address');
    expect(input.getAttribute('aria-describedby')).toContain(err.id);
  });

  it('composes cleanly with react-hook-form register() — spread + clone preserves both', () => {
    function Form({ onSubmit }: { onSubmit: (v: { name: string }) => void }) {
      const { register, handleSubmit } = useForm<{ name: string }>();
      return (
        <form onSubmit={handleSubmit(onSubmit)}>
          <FormField label="Name">
            <input {...register('name')} />
          </FormField>
          <button type="submit">Save</button>
        </form>
      );
    }
    let captured = '';
    render(<Form onSubmit={(v) => { captured = v.name; }} />);
    const input = screen.getByLabelText('Name');
    fireEvent.change(input, { target: { value: 'alice' } });
    fireEvent.click(screen.getByText('Save'));
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        expect(captured).toBe('alice');
        // Both RHF's name and FormField's id co-exist.
        expect(input.getAttribute('name')).toBe('name');
        expect(input.id).toMatch(/^field-/);
        resolve();
      }, 10);
    });
  });

  it('throws clearly when child is not a single valid element', () => {
    // Suppress React's error-boundary console spam for this assertion.
    const orig = console.error;
    console.error = () => {};
    try {
      expect(() =>
        render(
          <FormField label="Bad">
            {'plain string is not valid'}
          </FormField>,
        ),
      ).toThrow();
    } finally {
      console.error = orig;
    }
  });
});
