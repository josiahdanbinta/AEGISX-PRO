import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ThemeProvider, useTheme } from './ThemeContext';

function TestConsumer() {
  const { theme, setTheme } = useTheme();
  return (
    <div>
      <span data-testid="theme-value">{theme}</span>
      <button data-testid="set-dark" onClick={() => setTheme('dark')}>Set Dark</button>
    </div>
  );
}

function renderWithProvider() {
  return render(
    <ThemeProvider>
      <TestConsumer />
    </ThemeProvider>,
  );
}

describe('ThemeContext', () => {
  beforeEach(() => {
    document.documentElement.classList.remove('light', 'dark');
  });

  it('ThemeProvider forces dark theme on document element', () => {
    renderWithProvider();
    const theme = screen.getByTestId('theme-value').textContent;
    expect(theme).toBe('dark');
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('theme value is fixed dark and setTheme keeps it dark', async () => {
    renderWithProvider();
    await userEvent.click(screen.getByTestId('set-dark'));
    expect(screen.getByTestId('theme-value').textContent).toBe('dark');
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });
});
