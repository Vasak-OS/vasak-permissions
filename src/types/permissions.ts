/** Mirrors the shared `protocol` crate. */

export type Provenance = 'system-installed' | 'unverified';

export interface Application {
	binary_path: string;
	display_name: string;
	provenance: Provenance;
}

export interface PermissionRequest {
	application: Application;
	resource_id: string;
	detail: string;
}

/**
 * A request relayed by the desktop portal.
 *
 * The portal tells a backend only an `app_id`, which is empty for anything
 * outside a sandbox — so unlike a permission request, there is no program to
 * name. The dialog says that rather than leaving a blank where a name belongs.
 */
export interface PortalQuestion {
	app_id: string;
	title: string;
	subtitle: string;
	body: string;
}

export type Question =
	| ({ kind: 'permission' } & PermissionRequest)
	| ({ kind: 'portal' } & PortalQuestion);
