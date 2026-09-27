/** Identity of the API key currently in use (project + owner). */
import { request } from './client.js';

export interface Me {
  user?: { email?: string; name?: string } | null;
  project?: { id?: string; name?: string; slug?: string } | null;
}

export function me(): Promise<Me> {
  return request('GET', '/auth/me') as Promise<Me>;
}
