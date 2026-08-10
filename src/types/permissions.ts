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
