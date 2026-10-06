<?php

declare(strict_types=1);

T::group('OPNsense core compatibility');

// token_get_all() comes from the tokenizer extension, which a stock php:cli has but
// the firewall's PHP does not -- and README tells you to run this suite on the VM too.
// Without the guard the call is a fatal error that takes every later file down with it.
if (!function_exists('token_get_all')) {
	T::skip('does not call command helpers removed in OPNsense 26.4', 'no tokenizer extension');
	return;
}

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
