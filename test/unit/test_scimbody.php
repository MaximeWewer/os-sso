<?php

declare(strict_types=1);

use OPNsense\SSO\Api\ScimController;
use OPNsense\SSO\Scim\ScimError;

require_once dirname(__DIR__, 2) . '/src/opnsense/mvc/app/controllers/OPNsense/SSO/Api/ScimController.php';

T::group('SCIM request bounds: reject oversized input before JSON processing');

$originalLength = $_SERVER['CONTENT_LENGTH'] ?? null;
$limit = 1048576;
try {
	foreach ([
		['declared overflow', '{}', $limit + 1, 0],
		['missing length with an oversized body', str_repeat('x', $limit + 1), null, 1],
		['underreported length with an oversized body', str_repeat('x', $limit + 1), 2, 1],
	] as [$label, $rawBody, $declaredLength, $expectedReads]) {
		$request = new class ($rawBody) {
			public int $reads = 0;

			public function __construct(private string $rawBody)
			{
			}

			public function getRawBody(): string
			{
				$this->reads++;
				return $this->rawBody;
			}
		};
		if ($declaredLength === null) {
			unset($_SERVER['CONTENT_LENGTH']);
		} else {
			$_SERVER['CONTENT_LENGTH'] = (string)$declaredLength;
		}
		$controller = new ScimController();
		$controller->request = $request;
		$body = new ReflectionMethod($controller, 'body');
		try {
			$body->invoke($controller);
			T::ko($label, 'oversized request was accepted');
		} catch (ScimError $error) {
			eq(413, $error->status(), $label . ' returns Payload Too Large');
		}
		eq($expectedReads, $request->reads, $label . ' reads the body only when needed');
	}

	$boundaryBody = '{"v":"' . str_repeat('a', $limit - 8) . '"}';
	eq($limit, strlen($boundaryBody), 'the valid boundary fixture is exactly one MiB');
	$controller = new ScimController();
	$controller->request = new class ($boundaryBody) {
		public function __construct(private string $rawBody)
		{
		}

		public function getRawBody(): string
		{
			return $this->rawBody;
		}
	};
	$_SERVER['CONTENT_LENGTH'] = (string)$limit;
	$body = new ReflectionMethod($controller, 'body');
	eq($limit - 8, strlen($body->invoke($controller)['v']), 'valid JSON at the size limit remains accepted');
} finally {
	if ($originalLength === null) {
		unset($_SERVER['CONTENT_LENGTH']);
	} else {
		$_SERVER['CONTENT_LENGTH'] = $originalLength;
	}
}
