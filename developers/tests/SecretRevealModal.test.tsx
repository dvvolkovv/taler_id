import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SecretRevealModal } from '../src/modals/SecretRevealModal';

describe('SecretRevealModal', () => {
  beforeEach(() => cleanup());

  it('shows the secret in monospace', () => {
    render(<SecretRevealModal clientId="cid" clientSecret="SECRET123" onClose={() => {}} />);
    expect(screen.getByText('SECRET123')).toBeInTheDocument();
  });

  it('Done button is disabled until checkbox is ticked', async () => {
    const user = userEvent.setup();
    render(<SecretRevealModal clientId="cid" clientSecret="S" onClose={() => {}} />);
    const done = screen.getByRole('button', { name: /Done/i });
    expect(done).toBeDisabled();
    await user.click(screen.getByLabelText(/I've copied the secret/i));
    expect(done).toBeEnabled();
  });

  it('clicking Copy fires the clipboard API', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.spyOn(navigator.clipboard, 'writeText').mockImplementation(writeText);
    const user = userEvent.setup();
    render(<SecretRevealModal clientId="cid" clientSecret="S123" onClose={() => {}} />);
    await user.click(screen.getByRole('button', { name: /Copy/i }));
    expect(writeText).toHaveBeenCalledWith('S123');
  });

  it('Done button calls onClose', async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(<SecretRevealModal clientId="cid" clientSecret="S" onClose={onClose} />);
    await user.click(screen.getByLabelText(/I've copied the secret/i));
    await user.click(screen.getByRole('button', { name: /Done/i }));
    expect(onClose).toHaveBeenCalled();
  });
});
