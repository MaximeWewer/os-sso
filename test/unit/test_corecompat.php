<?php

declare(strict_types=1);

T::group('OPNsense core compatibility');

$deprecatedFunctions = ['mwexec', 'mwexec_bg'];
$deprecatedCalls = [];
$sourceRoot = dirname(__DIR__, 2) . '/src';
$files = new RecursiveIteratorIterator(
	new RecursiveDirectoryIterator($sourceRoot, FilesystemIterator::SKIP_DOTS),
);

foreach ($files as $file) {
	if (!$file->isFile() || !in_array($file->getExtension(), ['inc', 'php'], true)) {
		continue;
	}

	$tokens = token_get_all((string) file_get_contents($file->getPathname()));
	foreach ($tokens as $index => $token) {
		if (!is_array($token) || $token[0] !== T_STRING || !in_array($token[1], $deprecatedFunctions, true)) {
			continue;
		}

		$next = $index + 1;
		while (isset($tokens[$next]) && is_array($tokens[$next]) && in_array(
			$tokens[$next][0],
			[T_WHITESPACE, T_COMMENT, T_DOC_COMMENT],
			true,
		)) {
			$next++;
		}
		if (($tokens[$next] ?? null) === '(') {
			$deprecatedCalls[] = str_replace($sourceRoot . '/', '', $file->getPathname())
				. ':' . $token[2] . ' ' . $token[1] . '()';
		}
	}
}

eq([], $deprecatedCalls, 'does not call command helpers removed in OPNsense 26.4');

$pluginSource = (string) file_get_contents($sourceRoot . '/etc/inc/plugins.inc.d/sso.inc');
truthy(
	preg_match('/\\bmwexecf\\s*\\(/', $pluginSource),
	'uses the safe command wrapper available from OPNsense 25.7 through 26.4',
);
