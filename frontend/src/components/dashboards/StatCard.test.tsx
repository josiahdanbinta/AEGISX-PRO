import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { StatCard } from './StatCard';
import { Activity } from 'lucide-react';

describe('StatCard', () => {
  it('renders label and value', () => {
    render(<StatCard label="CPU Usage" value="78%" icon={Activity} />);
    expect(screen.getByText('CPU Usage')).toBeInTheDocument();
  });

  it('shows trend indicator', () => {
    render(
      <StatCard
        label="Alerts"
        value={42}
        icon={Activity}
        trend={{ value: '+12%', direction: 'up' }}
      />,
    );
    expect(screen.getByText('+12%')).toBeInTheDocument();
  });

  it('renders sparkline', () => {
    const { container } = render(
      <StatCard
        label="Network"
        value="1.2 GB"
        icon={Activity}
        sparklineData={[10, 20, 15, 30, 25, 40, 35]}
      />,
    );
    expect(container.querySelector('svg')).toBeInTheDocument();
  });

  it('applies accent border class', () => {
    const { container } = render(<StatCard label="Test" value="0" icon={Activity} accent="red" />);
    expect(container.firstChild).toHaveClass('border-l-red-500');
  });
});
