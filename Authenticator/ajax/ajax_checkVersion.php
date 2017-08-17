<?php
/**
 *  sysPass-Plugins
 *
 * @author nuxsmin
 * @link http://syspass.org
 * @copyright 2012-2017, Rubén Domínguez nuxsmin@syspass.org
 *
 * This file is part of sysPass-Plugins
 *
 * sysPass-Plugins is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * sysPass-Plugins is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with sysPass-Plugins. If not, see <http://www.gnu.org/licenses/>.
 */

use Plugins\Authenticator\AuthenticatorPlugin;
use SP\Http\JsonResponse;
use SP\Http\Request;
use SP\Util\Json;
use SP\Util\Util;

define('APP_ROOT', '../../../..');

require_once APP_ROOT . DIRECTORY_SEPARATOR . 'inc' . DIRECTORY_SEPARATOR . 'Base.php';

Request::checkReferer('GET');

session_write_close();

$JsonResponse = new JsonResponse();

try {
    $data = json_decode(Util::getDataFromUrl(AuthenticatorPlugin::VERSION_URL));

    $JsonResponse = new JsonResponse();
    $JsonResponse->setStatus(0);
    $JsonResponse->setData([$data]);

    Json::returnJson($JsonResponse);
} catch (\SP\Core\Exceptions\SPException $e) {
    Json::returnJson($JsonResponse);
}