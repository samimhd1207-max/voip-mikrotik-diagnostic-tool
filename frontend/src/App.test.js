import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import App from './App';

afterEach(() => {
  jest.restoreAllMocks();
});

test('renders one-page diagnostic form', () => {
  render(<App />);

  expect(screen.getByText(/MikroTik \/ VoIP Remote Diagnostic \(V1\)/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/Target IP or hostname/i)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /Run diagnostic/i })).toBeInTheDocument();
});

test('shows error when target is empty', async () => {
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: /Run diagnostic/i }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/Please enter a target IP address or hostname/i);
});

test('shows support-oriented analysis after successful run', async () => {
  const fetchMock = jest
    .spyOn(global, 'fetch')
    .mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: 'diag-1' }),
    })
    .mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        target: 'client.example.net',
        status: 'attention_required',
        analysis: {
          overallStatus: 'attention_required',
          primaryFinding: {
            probableCause: 'Winbox access (8291) appears blocked while web ports are reachable.',
            recommendedAction: 'Review firewall policy for management access and allowed source addresses.',
            mikrotikChecks: ['Inspect filter rules matching tcp dst-port=8291'],
            routerOsCommand: '/ip firewall filter print where chain=input',
          },
        },
        results: {
          ping: { ok: true },
          dns: { ok: true },
          ports: {
            ports: [
              { port: 80, open: true, responseTimeMs: 15 },
              { port: 443, open: true, responseTimeMs: 16 },
              { port: 8291, open: false, responseTimeMs: 20 },
              { port: 5060, open: false, responseTimeMs: 20 },
              { port: 5061, open: false, responseTimeMs: 20 },
            ],
          },
        },
      }),
    });

  render(<App />);
  fireEvent.change(screen.getByLabelText(/Target IP or hostname/i), {
    target: { value: 'client.example.net' },
  });
  fireEvent.click(screen.getByRole('button', { name: /Run diagnostic/i }));

  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));

  expect(screen.getByText(/Probable cause/i)).toBeInTheDocument();
  expect(screen.getByText(/Winbox access/i)).toBeInTheDocument();
  expect(screen.getByText(/Suggested MikroTik-side checks/i)).toBeInTheDocument();
  expect(screen.getByText(/8291/i)).toBeInTheDocument();
});