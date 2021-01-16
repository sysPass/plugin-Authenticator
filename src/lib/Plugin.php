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

namespace SP\Modules\Web\Plugins\Authenticator;

use Exception;
use Psr\Container\ContainerInterface;
use SP\Core\Context\ContextException;
use SP\Core\Context\ContextInterface;
use SP\Core\Context\SessionContext;
use SP\Core\Events\Event;
use SP\Core\Exceptions\ConstraintException;
use SP\Core\Exceptions\InvalidClassException;
use SP\Core\Exceptions\QueryException;
use SP\Core\UI\ThemeInterface;
use SP\Modules\Web\Plugins\Authenticator\Controllers\PreferencesController;
use SP\Modules\Web\Plugins\Authenticator\Models\AuthenticatorData;
use SP\Modules\Web\Plugins\Authenticator\Services\UpgradeService;
use SP\Modules\Web\Plugins\Authenticator\Util\PluginContext;
use SP\Mvc\Controller\ExtensibleTabControllerInterface;
use SP\Plugin\PluginBase;
use SP\Plugin\PluginOperation;
use SP\Repositories\NoSuchItemException;
use SplSubject;

/**
 * Class Plugin
 *
 * @package SP\Modules\Web\Plugins\Authenticator
 * @property AuthenticatorData $data
 */
class Plugin extends PluginBase
{
    const PLUGIN_NAME = 'Authenticator';
    const VERSION_URL = 'https://raw.githubusercontent.com/sysPass/plugin-Authenticator/master/version.json';
    const RECOVERY_GRACE_TIME = 86400;
    /**
     * @var ContainerInterface
     */
    private $dic;
    /**
     * @var SessionContext
     */
    private $session;

    /**
     * Receive update from subject
     *
     * @link  http://php.net/manual/en/splobserver.update.php
     *
     * @param SplSubject $subject <p>
     *                            The <b>SplSubject</b> notifying the observer of an update.
     *                            </p>
     *
     * @return void
     * @since 5.1.0
     */
    public function update(SplSubject $subject)
    {
    }

    /**
     * Inicialización del plugin
     *
     * @param ContainerInterface $dic
     */
    public function init(ContainerInterface $dic)
    {
        $this->base = dirname(__DIR__);
        $this->themeDir = $this->base . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . $dic->get(ThemeInterface::class)->getThemeName();

        $this->setLocales();

        $this->dic = $dic;

        $this->session = $this->dic->get(ContextInterface::class);
    }

    /**
     * Evento de actualización
     *
     * @param string $eventType Nombre del evento
     * @param Event  $event     Objeto del evento
     *
     * @throws InvalidClassException
     * @throws Exception
     */
    public function updateEvent($eventType, Event $event)
    {
        switch ($eventType) {
            case 'show.userSettings':
                $this->loadData();
                (new PreferencesController(
                    $event->getSource(ExtensibleTabControllerInterface::class),
                    $this,
                    $this->dic)
                )->setUp();
                break;
            case 'login.finish':
                $this->loadData();
                $this->checkLogin($event);
                break;
        }
    }

    /**
     * Load plugin's data for current user
     */
    private function loadData()
    {
        try {
            $this->data = $this->pluginOperation->get(
                $this->session->getUserData()->getId(),
                AuthenticatorData::class
            );
        } catch (Exception $e) {
            processException($e);
        }
    }

    /**
     * Comprobar 2FA en el login
     *
     * @param Event $event
     *
     * @throws ContextException
     */
    private function checkLogin(Event $event)
    {
        $pluginContext = $this->dic->get(PluginContext::class);

        if ($this->data !== null
            && $this->data->isTwofaEnabled()
        ) {
            $pluginContext->setTwoFApass(false);
            $this->session->setAuthCompleted(false);

            $eventData = $event->getEventMessage()->getExtra();

            if (isset($eventData['redirect'][0])
                && is_callable($eventData['redirect'][0])
            ) {
                $this->session->setTrasientKey('redirect', $eventData['redirect'][0]('authenticatorLogin/index'));
            } else {
                $this->session->setTrasientKey('redirect', 'index.php?r=authenticatorLogin/index');
            }
        } else {
            $pluginContext->setTwoFApass(true);
            $this->session->setAuthCompleted(true);
        }
    }

    /**
     * @return AuthenticatorData
     */
    public function getData()
    {
        if ($this->data === null
            && $this->session->isLoggedIn()
            && $this->pluginOperation !== null
        ) {
            $this->loadData();
        }

        return parent::getData();
    }

    /**
     * Devuelve los eventos que implementa el observador
     *
     * @return array
     */
    public function getEvents()
    {
        return ['show.userSettings', 'login.finish'];
    }

    /**
     * Devuelve los recursos JS y CSS necesarios para el plugin
     *
     * @return array
     */
    public function getJsResources()
    {
        return ['plugin.min.js'];
    }

    /**
     * Devuelve el autor del plugin
     *
     * @return string
     */
    public function getAuthor()
    {
        return 'Rubén D.';
    }

    /**
     * Devuelve la versión del plugin
     *
     * @return array
     */
    public function getVersion()
    {
        return [2, 2, 1];
    }

    /**
     * Devuelve la versión compatible de sysPass
     *
     * @return array
     */
    public function getCompatibleVersion()
    {
        return [3, 2];
    }

    /**
     * Devuelve los recursos CSS necesarios para el plugin
     *
     * @return array
     */
    public function getCssResources()
    {
        return ['plugin.min.css'];
    }

    /**
     * Devuelve el nombre del plugin
     *
     * @return string
     */
    public function getName()
    {
        return self::PLUGIN_NAME;
    }

    /**
     * Eliminar los datos de un Id
     *
     * @param $id
     *
     * @throws ConstraintException
     * @throws QueryException
     * @throws NoSuchItemException
     */
    public function deleteDataForId($id)
    {
        $this->pluginOperation->delete((int)$id);
    }

    /**
     * onLoad
     */
    public function onLoad()
    {
        $this->loadData();
    }

    /**
     * @param string          $version
     * @param PluginOperation $pluginOperation
     * @param mixed           $extra
     *
     * @throws Services\AuthenticatorException
     */
    public function upgrade(string $version, PluginOperation $pluginOperation, $extra = null)
    {
        switch ($version) {
            case '310.19012201':
                (new UpgradeService($pluginOperation))->upgrade_310_19012201($extra);
                break;
        }
    }
}