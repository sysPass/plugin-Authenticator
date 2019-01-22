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

namespace SP\Modules\Web\Plugins\Authenticator\Controllers;

use Psr\Container\ContainerInterface;
use SP\Core\Context\ContextInterface;
use SP\Core\Events\Event;
use SP\Modules\Web\Plugins\Authenticator\Services\AuthenticatorService;
use SP\Modules\Web\Plugins\Authenticator\Util\PluginContext;
use SP\Mvc\Controller\ExtensibleTabControllerInterface;
use SP\Mvc\View\Components\DataTab;
use SP\Mvc\View\Template;
use SP\Plugin\PluginInterface;
use SP\Util\ErrorUtil;

/**
 * Class Controller
 *
 * @package Plugins\Authenticator
 */
final class PreferencesController
{
    /**
     * @var AuthenticatorService
     */
    private $authenticatorService;
    /**
     * @var PluginContext
     */
    private $pluginContext;
    /**
     * @var ExtensibleTabControllerInterface
     */
    private $controller;
    /**
     * @var PluginInterface
     */
    private $plugin;
    /**
     * @var Template
     */
    private $view;
    /**
     * @var ContextInterface
     */
    private $context;

    /**
     * Controller constructor.
     *
     * @param ExtensibleTabControllerInterface $controller
     * @param PluginInterface                  $plugin
     * @param ContainerInterface               $dic
     */
    public function __construct(ExtensibleTabControllerInterface $controller, PluginInterface $plugin, ContainerInterface $dic)
    {
        $this->controller = $controller;
        $this->plugin = $plugin;
        $this->context = $dic->get(ContextInterface::class);
        $this->view = $controller->getView();
        $this->pluginContext = $dic->get(PluginContext::class);
        $this->authenticatorService = $dic->get(AuthenticatorService::class);
    }

    /**
     * @throws \Exception
     */
    public function setUp()
    {
        $this->controller->addTab($this->getSecurityTab());
    }

    /**
     * Builds the security tab
     *
     * @return DataTab
     */
    protected function getSecurityTab()
    {
        $base = $this->plugin->getThemeDir() . DIRECTORY_SEPARATOR . 'views' . DIRECTORY_SEPARATOR . 'userpreferences';

        $template = clone $this->view;
        $template->setBase($base);
        $template->addTemplate('preferences-security');

        try {
            // Datos del usuario de la sesión
            $userData = $this->context->getUserData();

            $authenticatorData = $this->plugin->getData();

            $qrCode = '';

            if (!$authenticatorData->isTwofaEnabled()) {
                $authenticatorData->setIV(AuthenticatorService::makeInitializationKey());

                $this->pluginContext->setUserData($authenticatorData);

//                $qrCode = $this->authenticatorService->getQrCodeFromUrl($userData->getLogin(), $authenticatorData->getIV());
                $qrCode = $this->authenticatorService->getQrCodeFromServer($userData->getLogin(), $authenticatorData->getIV());
            } elseif ($authenticatorData->isTwofaEnabled()
                && $authenticatorData->getUserId() > 0
            ) {
                $this->pluginContext->setUserData($authenticatorData);
            }

            $template->assign('qrCode', $qrCode);
            $template->assign('userId', $userData->getId());
            $template->assign('chk2FAEnabled', $authenticatorData->isTwofaEnabled());
            $template->assign('expireDays', $authenticatorData->getExpireDays());
            $template->assign('route', 'authenticator/save');
            $template->assign('viewCodesRoute', 'authenticator/showRecoveryCodes');
        } catch (\Exception $e) {
            processException($e);

            $this->controller
                ->getEventDispatcher()
                ->notifyEvent('exception', new Event($e));

            ErrorUtil::showExceptionInView($template, $e, null, false);
        }

        return new DataTab(_t('authenticator', 'Security'), $template);
    }
}