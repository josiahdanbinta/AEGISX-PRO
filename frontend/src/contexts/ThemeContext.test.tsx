import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ThemeProvider, useTheme } from './ThemeContext';

function TestConsumer() {
  const { theme, toggleTheme, setTheme } = useTheme();
  return (
    <div>
      <span data-testid="theme-value">{theme}</span>
      <button data-testid="toggle-btn" onClick={toggleTheme}>Toggle</button>
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
    localStorage.clear();
    document.documentElement.classList.remove('light', 'dark');
  });

  it('ThemeProvider sets theme class on document element', () => {
    renderWithProvider();
    const theme = screen.getByTestId('theme-value').textContent;
    expect(
      document.documentElement.classList.contains('light') ||
      document.documentElement.classList.contains('dark'),
    ).toBe(true);
  });

  it('toggles theme between light and dark', async () => {
    renderWithProvider();
    const initial = screen.getByTestId('theme-value').textContent;
    const toggleBtn = screen.getByTestId('toggle-btn');
    await userEvent.click(toggleBtn);
    expect(screen.getByTestId('theme-value').textContent).not.toBe(initial);
  });

  it('setTheme allows setting a specific theme', async () => {
    renderWithProvider();
    await userEvent.click(screen.getByTestId('set-dark'));
    expect(screen.getByTestId('theme-value').textContent).toBe('dark');
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('persists theme to localStorage after toggle', async () => {
    renderWithProvider();
    await userEvent.click(screen.getByTestId('toggle-btn'));
    const stored = localStorage.getItem('AEGIS-theme');
    expect(stored).toBeTruthy();
    expect(stored === 'light' || stored === 'dark').toBe(true);
  });
});
