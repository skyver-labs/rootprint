import type { LayoutLoad } from './$types';

/**
 * Where the client-side admin gate used to be.
 *
 * It read `session.user.role !== 'admin'` and redirected. That role was a column
 * this console owned — the second authority the fork exists to remove — so the
 * check is gone rather than reimplemented against something else.
 *
 * Nothing is lost by that: a client-side redirect never protected these pages.
 * Each one loads from an endpoint that authorizes the request on its own, and a
 * refusal renders as a refusal. What a client-side gate does is avoid showing
 * somebody a screen they cannot use, and restoring that is a Phase 2 change —
 * when the server can answer "may this principal operate?", the answer belongs
 * here, asked of Tunda rather than of a local field.
 *
 * The file stays, empty, because this is where somebody will look for the gate.
 */
export const load: LayoutLoad = async () => ({});
