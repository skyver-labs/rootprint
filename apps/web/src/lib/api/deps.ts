export const DEP = {
	session: 'app:session',
	indexes: 'app:indexes',
	index: (id: string): `app:index:${string}` => `app:index:${id}`
} as const;
