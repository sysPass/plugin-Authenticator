<?php

$lib = __DIR__ . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'lib';

$base = [
    'namespace' => 'SP\Modules\\Web\\Plugins\\Authenticator\\',
    'dir' => $lib
];

/** @var \Composer\Autoload\ClassLoader $loader */
$loader = require APP_ROOT . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';
$loader->addPsr4($base['namespace'], $base['dir']);
$loader->addClassMap([
    \SP\Modules\Web\Controllers\AuthenticatorController::class => $lib . DIRECTORY_SEPARATOR . 'Controllers' . DIRECTORY_SEPARATOR . 'AuthenticatorController.php',
    \SP\Modules\Web\Controllers\AuthenticatorLoginController::class => $lib . DIRECTORY_SEPARATOR . 'Controllers' . DIRECTORY_SEPARATOR . 'AuthenticatorLoginController.php'
]);

return $base;