/** API key endpoints (/api/v1/keys). */
import { request } from './client.js';

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  is_live?: boolean;
  created_at: string;
}

export function list(): Promise<{ keys: ApiKey[] }> {
  return request('GET', '/keys');
}

export function create(name: string, isLive = true): Promise<{ id: string; name: string; key: string; key_prefix: string }> {
  return request('POST', '/keys', { body: { name, is_live: isLive } });
}

export function revoke(id: string): Promise<unknown> {
  return request('DELETE', `/keys/${encodeURIComponent(id)}`);
}
