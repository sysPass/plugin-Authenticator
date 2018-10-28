<?php
/**
 *  sysPass-Authenticator
 *
 * @author    nuxsmin
 * @link      http://syspass.org
 * @copyright 2012-2017, Rubén Domínguez nuxsmin@syspass.org
 *
 * This file is part of sysPass-Authenticator.
 *
 * sysPass-Authenticator is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * sysPass-Authenticator is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with sysPass-Authenticator. If not, see <http://www.gnu.org/licenses/>.
 */

namespace SP\Modules\Web\Controllers;

use SP\Core\Events\Event;
use SP\Core\Events\EventMessage;
use SP\Modules\Web\Controllers\Helpers\LayoutHelper;
use SP\Modules\Web\Controllers\Traits\JsonTrait;
use SP\Modules\Web\Plugins\Authenticator\Plugin;
use SP\Plugin\PluginManager;

/**
 * Class LoginController
 *
 * @package Plugins\Authenticator
 */
final class AuthenticatorLoginController extends ControllerBase
{
    use JsonTrait;

    const WARNING_TIME = 432000;

    /**
     * @var Plugin
     */
    private $plugin;

    /**
     * Obtener los datos para el interface de autentificación en 2 pasos
     *
     * @throws \DI\DependencyException
     * @throws \DI\NotFoundException
     * @throws \SP\Services\Auth\AuthException
     */
    public function indexAction()
    {
        $this->checkLoggedIn(false);

        $layoutHelper = $this->dic->get(LayoutHelper::class);
        $this->view->addTemplate('main', '_layouts');

        $this->view->addContentTemplate('index', $this->plugin->getThemeDir() . DIRECTORY_SEPARATOR . 'views' . DIRECTORY_SEPARATOR . 'login');

        $layoutHelper->setPage('authenticator-2fa');
        $layoutHelper->initBody();

        $this->view->assign('useFixedHeader', true);
        $this->view->assign('useMenu', false);
        $this->view->assign('route', 'authenticator/checkCode');

        $this->checkExpireTime($this->userData->getId());

        $this->prepareSignedUriOnView();

        $this->view();
    }

    /**
     * Comprobar la caducidad del código
     *
     * @param $userId
     */
    protected function checkExpireTime($userId)
    {
        $data = $this->plugin->getDataForId($userId);

        if ($data === null || empty($data->getExpireDays())) {
            return;
        }

        $expireTime = $data->getDate() + ($data->getExpireDays() * 86400);
        $timeRemaining = $expireTime - time();

        if ($timeRemaining <= self::WARNING_TIME) {
            $this->eventDispatcher->notifyEvent('authenticator.expiry.notice',
                new Event($this, EventMessage::factory()
                    ->addDescription(_t('authenticator', 'Aviso Caducidad'))
                    ->addDescription(sprintf(_t('authenticator', 'El código 2FA se ha de restablecer en %d días'), $timeRemaining / 86400)))
            );
        } elseif (time() > $expireTime) {
            $this->eventDispatcher->notifyEvent('authenticator.expiry.notice',
                new Event($this, EventMessage::factory()
                    ->addDescription(_t('authenticator', 'Aviso Caducidad'))
                    ->addDescription(_t('authenticator', 'El código 2FA ha caducado. Es necesario restablecerlo desde las preferencias')))
            );
        }
    }

    /**
     * @throws \DI\DependencyException
     * @throws \DI\NotFoundException
     */
    protected function initialize()
    {
        $this->plugin = $this->dic->get(PluginManager::class)
            ->getPluginInfo(Plugin::PLUGIN_NAME);
    }
}