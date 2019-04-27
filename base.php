<?php
/**
 * sysPass
 *
 * @author nuxsmin
 * @link https://syspass.org
 * @copyright 2012-2019, Rubén Domínguez nuxsmin@$syspass.org
 *
 * This file is part of sysPass.
 *
 * sysPass is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * sysPass is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *  along with sysPass.  If not, see <http://www.gnu.org/licenses/>.
 */

$lib = __DIR__ . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'lib';

$base = [
    'namespace' => 'SP\Modules\\Web\\Plugins\\Authenticator\\',
    'dir' => $lib
];

if (!class_exists(\SP\Modules\Web\Plugins\Authenticator\Plugin::class)) {
    /** @var \Composer\Autoload\ClassLoader $loader */
    $loader = require APP_ROOT . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';
    $loader->addPsr4($base['namespace'], $base['dir']);
    $loader->addClassMap([
        \SP\Modules\Web\Controllers\AuthenticatorController::class => $lib . DIRECTORY_SEPARATOR . 'Controllers' . DIRECTORY_SEPARATOR . 'AuthenticatorController.php',
        \SP\Modules\Web\Controllers\AuthenticatorLoginController::class => $lib . DIRECTORY_SEPARATOR . 'Controllers' . DIRECTORY_SEPARATOR . 'AuthenticatorLoginController.php'
    ]);
}

return $base;