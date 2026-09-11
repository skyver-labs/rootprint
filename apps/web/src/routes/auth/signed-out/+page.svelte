<script lang="ts">
	import { loginUrl } from '$lib/api/session';
</script>

<svelte:head><title>Signed out</title></svelte:head>

<div class="flex flex-col items-center gap-6 px-4 py-12 text-center">
	<div class="flex flex-col gap-2">
		<h1 class="text-h1">Signed out</h1>
		<p class="text-base-content/60 max-w-sm text-sm">
			Your session here has ended, and so has your session with Tunda.
		</p>
	</div>

	<a class="btn btn-primary" href={loginUrl('/')}>Sign in with Tunda</a>
</div>
