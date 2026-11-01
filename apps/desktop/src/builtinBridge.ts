import { Channel, invoke } from '@tauri-apps/api/core';
import { isTauri, type TraceEvidence } from './bridge';
export type ConnectionId = 'openai' | 'anthropic' | 'chatgpt';
export type Connection = { id: ConnectionId; status: string };
export type ChatMessage = { role: 'user' | 'assistant'; content: string };
export type ChatTrace = {
  id: string;
  captured: boolean;
  /** Read from the local service once the Trace is confirmed. */
  evidence?: TraceEvidence;
};
export type ChatResult = {
  status: string;
  traces: ChatTrace[];
};
export type DeviceLogin = {
  login_id: string;
  user_code: string;
  verification_url: string;
};
const native = <T>(command: string, args?: Record<string, unknown>): Promise<T> =>
  isTauri()
    ? invoke<T>(command, args)
    : Promise.reject(new Error('Open Exalto Capture on your Mac to connect and chat.'));
export const listConnections = () =>
  isTauri() ? native<Connection[]>('list_provider_connections') : Promise.resolve([]);
export const chatgptStatus = () =>
  isTauri() ? native<string>('chatgpt_status') : Promise.resolve('disconnected');
export const saveConnection = (provider: Exclude<ConnectionId, 'chatgpt'>, apiKey: string) =>
  native<void>('save_provider_connection', { provider, apiKey });
export const removeConnection = (id: ConnectionId) =>
  id === 'chatgpt'
    ? native<void>('disconnect_chatgpt')
    : native<void>('remove_provider_connection', { provider: id });
export const startChatgptLogin = () => native<DeviceLogin>('start_chatgpt_login');
export const cancelChatgptLogin = (loginId: string) =>
  native<void>('cancel_chatgpt_login', { loginId });
export const openVerification = (url: string) => native<void>('open_chatgpt_verification', { url });
export const cancelChat = (requestId: string) => native<void>('cancel_chat', { requestId });
export const sendChat = (
  requestId: string,
  connectionId: ConnectionId,
  model: string,
  messages: ChatMessage[],
  onDelta: (text: string) => void,
) => {
  const events = new Channel<{ type: 'delta'; text: string }>();
  events.onmessage = (event) => {
    if (event.type === 'delta') onDelta(event.text);
  };
  return native<ChatResult>('send_chat', {
    requestId,
    connectionId,
    model,
    messages,
    events,
  });
};

export type ChatModel = { id: string; name: string; is_default: boolean };
export const listModels = (connectionId: ConnectionId) =>
  native<ChatModel[]>('list_chat_models', { connectionId });

export const unlockConnections = () => native<void>('unlock_provider_connections');
