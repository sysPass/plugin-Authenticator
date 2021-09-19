<?php
/**
 * sysPass
 *
 * @author    nuxsmin
 * @link      https://syspass.org
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

namespace SP\Modules\Web\Controllers;

use DI\DependencyException;
use DI\NotFoundException;
use SP\Core\Events\Event;
use SP\Core\Events\EventMessage;
use SP\Core\Exceptions\SessionTimeout;
use SP\Modules\Web\Controllers\Helpers\LayoutHelper;
use SP\Modules\Web\Controllers\Traits\JsonTrait;
use SP\Modules\Web\Plugins\Authenticator\Plugin;
use SP\Plugin\PluginManager;
use SP\Services\Auth\AuthException;

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
     * @throws DependencyException
     * @throws NotFoundException
     * @throws SessionTimeout
     * @throws AuthException
     * @throws SessionTimeout
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
        $this->view->assign('isMailEnabled', $this->configData->isMailEnabled());
        $this->view->assign('recoveryGraceTime', Plugin::RECOVERY_GRACE_TIME / 3600);

        $this->checkExpireTime();

        $this->prepareSignedUriOnView();

        $this->view();
    }

    /**
     * Comprobar la caducidad del código
     */
    protected function checkExpireTime()
    {
        $data = $this->plugin->getData();

        if ($data === null || empty($data->getExpireDays())) {
            return;
        }

        $expireTime = $data->getDate() + ($data->getExpireDays() * 86400);
        $timeRemaining = $expireTime - time();

        if ($timeRemaining <= self::WARNING_TIME) {
            $this->eventDispatcher->notifyEvent('authenticator.expiry.warn',
                new Event($this, EventMessage::factory()
                    ->addDescription(_t('authenticator', 'Aviso de Expiração'))
                    ->addDescription(sprintf(_t('authenticator',
                        'O código 2FA terá de ser reposto dentro de %d dias'), $timeRemaining / 86400))
                    ->addDetail(__('User'), $this->userData->getLogin())
                    ->addExtra('userId', $this->userData->getId())
                )
            );
        } elseif (time() > $expireTime) {
            $this->eventDispatcher->notifyEvent('authenticator.expiry.expired',
                new Event($this, EventMessage::factory()
                    ->addDescription(_t('authenticator', 'Aviso de expiração'))
                    ->addDescription(_t('authenticator',
                        'O código 2FA está expirado. É necessário redefini-lo no separador das preferências'))
                    ->addDetail(__('User'), $this->userData->getLogin())
                    ->addExtra('userId', $this->userData->getId())
                )
            );
        }
    }

    /**
     * @throws DependencyException
     * @throws NotFoundException
     */
    protected function initialize()
    {
        $this->plugin = $this->dic->get(PluginManager::class)
            ->getPlugin(Plugin::PLUGIN_NAME);
    }
}
