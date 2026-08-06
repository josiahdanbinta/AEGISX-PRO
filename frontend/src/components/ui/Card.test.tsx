import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Card, CardHeader, CardTitle } from './Card';

describe('Card', () => {
  it('renders children', () => {
    render(<Card>Card Content</Card>);
    expect(screen.getByText('Card Content')).toBeInTheDocument();
  });

  it('applies padding classes', () => {
    const { container } = render(<Card padding="sm">Padded</Card>);
    expect(container.firstChild).toHaveClass('p-4');
  });

  it('applies accent border classes', () => {
    const { container } = render(<Card accent="red">Accent</Card>);
    expect(container.firstChild).toHaveClass('border-l-4');
    expect(container.firstChild).toHaveClass('border-l-red-500');
  });

  it('applies hover class', () => {
    const { container } = render(<Card hover>Hoverable</Card>);
    expect(container.firstChild).toHaveClass('hover:-translate-y-0.5');
  });
});

describe('CardHeader', () => {
  it('renders children', () => {
    render(<CardHeader>Header Content</CardHeader>);
    expect(screen.getByText('Header Content')).toBeInTheDocument();
  });
});

describe('CardTitle', () => {
  it('renders children', () => {
    render(<CardTitle>Card Title Text</CardTitle>);
    expect(screen.getByText('Card Title Text')).toBeInTheDocument();
  });
});
