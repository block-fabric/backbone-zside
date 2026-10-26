// The shielded account as the pages share it: read again when the node said something changed (drop.version).
import { errorText } from '../../lib/dialogs.svelte';
import { drop } from '../dropin/store.svelte';
import { zs, type Shielded } from './api';

export const shielded = $state({ data: null as Shielded | null, error: '', version: -1 });

let reading: Promise<void> | null = null;

/** Read the shielded account, once per change the node told of. */
export function readShielded(force = false): Promise<void> {
  if (!force && shielded.version === drop.version && shielded.data) return Promise.resolve();
  if (reading) return reading;
  const v = drop.version;
  reading = zs
    .shielded()
    .then((d) => {
      shielded.data = d;
      shielded.error = '';
      shielded.version = v;
    })
    .catch((e) => {
      shielded.error = errorText(e);
    })
    .finally(() => {
      reading = null;
    });
  return reading;
}
