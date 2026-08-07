import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Input } from './Input';

describe('Input', () => {
  it('renders label', () => {
    render(<Input label="Email Address" />);
    expect(screen.getByLabelText('Email Address')).toBeInTheDocument();
  });

  it('shows error text', () => {
    render(<Input label="Email" error="This field is required" />);
    expect(screen.getByText('This field is required')).toBeInTheDocument();
  });

  it('applies error styles', () => {
    const { container } = render(<Input error="Invalid" />);
    expect(container.querySelector('input')).toHaveClass('border-red-800');
  });

  it('shows hint text when no error', () => {
    render(<Input label="Name" hint="Enter your full name" />);
    expect(screen.getByText('Enter your full name')).toBeInTheDocument();
  });

  it('does not show hint when error is present', () => {
    render(<Input label="Name" hint="Helpful hint" error="Required" />);
    expect(screen.queryByText('Helpful hint')).not.toBeInTheDocument();
  });
});
