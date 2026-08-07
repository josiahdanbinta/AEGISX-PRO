import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Badge } from './Badge';

describe('Badge', () => {
  it('renders children text', () => {
    render(<Badge>Test</Badge>);
    expect(screen.getByText('Test')).toBeInTheDocument();
  });

  it('applies variant classes', () => {
    const { container } = render(<Badge variant="danger">Danger</Badge>);
    expect(container.firstChild).toHaveClass('bg-red-900/50');
  });

  it('applies size classes', () => {
    const { container } = render(<Badge size="sm">Small</Badge>);
    expect(container.firstChild).toHaveClass('text-[10px]');
  });

  it('applies custom className', () => {
    const { container } = render(<Badge className="my-custom">Custom</Badge>);
    expect(container.firstChild).toHaveClass('my-custom');
  });
});
