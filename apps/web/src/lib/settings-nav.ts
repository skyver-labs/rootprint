import { LayoutDashboard, Activity, Database, Send } from 'lucide-svelte';
import type { BreadcrumbSegment } from '$lib/types';

export type NavItem = { href: string; label: string; icon: typeof LayoutDashboard };
export type NavGroup = { label: string; items: NavItem[] };

/**
 * Settings sidebar nav tree. Shared with breadcrumbs so the two cannot drift.
 *
 * Four entries are gone rather than hidden: Profile (password and personal API
 * keys), API keys, Service accounts, Users and Authentication (Google and GitHub
 * provider configuration). Each administered something this console no longer
 * owns. A person is administered in Tunda; so is a producer's credential.
 *
 * `adminOnly` is gone with them. It filtered this list on a local `role` column,
 * and there is no local role — see `routes/(app)/settings/(admin)/+layout.ts` for
 * what replaces the gate and when.
 */
export const navGroups: NavGroup[] = [
	{
		label: 'Cluster',
		items: [
			{ href: '/settings/overview', label: 'Overview', icon: LayoutDashboard },
			{ href: '/settings/activity', label: 'Activity', icon: Activity }
		]
	},
	{
		label: 'Data',
		items: [
			{ href: '/settings/send-telemetry', label: 'Send logs & traces', icon: Send },
			{ href: '/settings/indexes', label: 'Indexes', icon: Database }
		]
	}
];

// Shared ancestor crumbs — defined once, reused across trails.
const ROOT: BreadcrumbSegment = { label: 'Settings', href: '/settings' };
const ACTIVITY: BreadcrumbSegment = { label: 'Activity', href: '/settings/activity' };
const INDEXES: BreadcrumbSegment = { label: 'Indexes', href: '/settings/indexes' };
const SEND_TELEMETRY: BreadcrumbSegment = {
	label: 'Send logs & traces',
	href: '/settings/send-telemetry'
};

type Params = Record<string, string | undefined>;

/** Breadcrumb trails keyed by clean route pattern (`(group)` segments stripped). The only place breadcrumb structure lives — add new settings pages here. */
const TRAILS: Record<string, (params: Params) => BreadcrumbSegment[]> = {
	'/settings/overview': () => [ROOT, { label: 'Overview' }],
	'/settings/activity': () => [ROOT, { label: 'Activity' }],
	// Audit drill-downs. `api-keys/[id]` reaches search_audit rows recorded before
	// the fork, when this console issued query keys — the rows survive, the
	// credential does not.
	'/settings/activity/api-keys/[id]': () => [ROOT, ACTIVITY, { label: 'API key' }],
	'/settings/activity/users/[userId]': () => [ROOT, ACTIVITY, { label: 'Operator' }],
	'/settings/indexes': () => [ROOT, { label: 'Indexes' }],
	'/settings/indexes/_new': () => [ROOT, INDEXES, { label: 'New index' }],
	'/settings/indexes/[indexId]': (p) => [
		ROOT,
		INDEXES,
		{ label: p.indexId ?? 'Index', mono: true }
	],
	'/settings/indexes/[indexId]/edit': (p) => [
		ROOT,
		INDEXES,
		{ label: p.indexId ?? 'Index', href: `/settings/indexes/${p.indexId}`, mono: true },
		{ label: 'Edit' }
	],
	'/settings/indexes/[indexId]/sources/new': (p) => [
		ROOT,
		INDEXES,
		{ label: p.indexId ?? 'Index', href: `/settings/indexes/${p.indexId}?tab=sources`, mono: true },
		{ label: 'New source' }
	],
	'/settings/indexes/[indexId]/sources/[sourceId]': (p) => [
		ROOT,
		INDEXES,
		{ label: p.indexId ?? 'Index', href: `/settings/indexes/${p.indexId}?tab=sources`, mono: true },
		{ label: p.sourceId ?? 'Source', mono: true }
	],
	'/settings/send-telemetry': () => [ROOT, { label: 'Send logs & traces' }],
	'/settings/send-telemetry/[integration]': (p) => [
		ROOT,
		SEND_TELEMETRY,
		{ label: p.integration ?? 'Integration' }
	]
};

export function routeKey(routeId: string): string {
	return routeId.replace(/\/\([^)]+\)/g, '');
}

export function resolveBreadcrumbs(
	routeId: string | null,
	params: Params = {}
): BreadcrumbSegment[] {
	if (!routeId) return [];
	const build = TRAILS[routeKey(routeId)];
	return build ? build(params) : [];
}
