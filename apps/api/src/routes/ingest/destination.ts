/**
 * The header a producer names its destination index with.
 *
 * Only consulted when the token already permits more than one destination for the
 * signal, and only ever used to *choose among* what the token grants — never to
 * introduce one. A header naming an index the token does not carry resolves to
 * nothing and the batch is refused, which is the property that lets this be an
 * ordinary unauthenticated header at all.
 */
export const INDEX_HEADER = 'x-tunda-index';
