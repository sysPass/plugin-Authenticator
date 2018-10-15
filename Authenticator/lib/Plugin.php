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

namespace SP\Modules\Web\Plugins\Authenticator;

use Psr\Container\ContainerInterface;
use SP\Core\Context\ContextInterface;
use SP\Core\Events\Event;
use SP\Core\UI\Theme;
use SP\DataModel\PluginData;
use SP\Modules\Web\Plugins\Authenticator\Controllers\PreferencesController;
use SP\Modules\Web\Plugins\Authenticator\Models\AuthenticatorData;
use SP\Modules\Web\Plugins\Authenticator\Util\PluginContext;
use SP\Mvc\Controller\ExtensibleTabControllerInterface;
use SP\Plugin\PluginBase;
use SP\Util\Util;
use SplSubject;

/**
 * Class Plugin
 *
 * @package SP\Modules\Web\Plugins\Authenticator
 */
class Plugin extends PluginBase
{
    const PLUGIN_NAME = 'Authenticator';
    const VERSION_URL = 'https://raw.githubusercontent.com/nuxsmin/sysPass-Plugins/master/version.json';
    const RECOVERY_GRACE_TIME = 86400;
    /**
     * @var ContainerInterface
     */
    private $dic;

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
        if (!is_array($this->data)) {
            $this->data = [];
        }

        $this->base = dirname(__DIR__);
        $this->themeDir = $this->base . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . $dic->get(Theme::class)->getThemeName();

        $this->setLocales();

        $this->dic = $dic;
    }

    /**
     * Evento de actualización
     *
     * @param string $eventType Nombre del evento
     * @param Event  $event     Objeto del evento
     *
     * @throws \SP\Core\Exceptions\InvalidClassException
     * @throws \Exception
     */
    public function updateEvent($eventType, Event $event)
    {
        switch ($eventType) {
            case 'show.userSettings':
                /** @var ExtensibleTabControllerInterface $source */
                $source = $event->getSource(ExtensibleTabControllerInterface::class);

                (new PreferencesController($source, $this, $this->dic))
                    ->setUp();
                break;
            case 'login.finish':
                $this->checkLogin($event);
                break;
        }
    }

    /**
     * Comprobar 2FA en el login
     *
     * @param Event $event
     *
     * @throws \SP\Core\Context\ContextException
     */
    private function checkLogin(Event $event)
    {
        $session = $this->dic->get(ContextInterface::class);
        $pluginContext = $this->dic->get(PluginContext::class);

        $data = $this->getDataForId($session->getUserData()->getId());

        if ($data !== null && $data->isTwofaEnabled()) {
            $pluginContext->setTwoFApass(false);
            $session->setAuthCompleted(false);

            $eventData = $event->getEventMessage()->getData();

            if (isset($eventData['redirect'][0])
                && is_callable($eventData['redirect'][0])
            ) {
                $session->setTrasientKey('redirect', $eventData['redirect'][0]('authenticatorLogin/index'));
            } else {
                $session->setTrasientKey('redirect', 'index.php?r=authenticatorLogin/index');
            }
        } else {
            $pluginContext->setTwoFApass(true);
            $session->setAuthCompleted(true);
        }
    }

    /**
     * Devolver los datos de un Id
     *
     * @param $id
     *
     * @return AuthenticatorData|null
     */
    public function getDataForId($id)
    {
        return isset($this->data[$id]) ? $this->data[$id] : null;
    }

    /**
     * @return array|AuthenticatorData[]
     */
    public function getData()
    {
        return (array)parent::getData();
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
        return [2, 0, 0];
    }

    /**
     * Devuelve la versión compatible de sysPass
     *
     * @return array
     */
    public function getCompatibleVersion()
    {
        return [3, 0];
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
     * Establecer los datos de un Id
     *
     * @param                   $id
     * @param AuthenticatorData $AuthenticatorData
     *
     * @return Plugin
     */
    public function setDataForId($id, AuthenticatorData $AuthenticatorData)
    {
        $this->data[$id] = $AuthenticatorData;

        return $this;
    }

    /**
     * Eliminar los datos de un Id
     *
     * @param $id
     */
    public function deleteDataForId($id)
    {
        if (isset($this->data[$id])) {
            unset($this->data[$id]);
        }
    }

    /**
     * @param mixed $pluginData
     */
    public function onLoadData(PluginData $pluginData)
    {
        $this->data = Util::unserialize(
            AuthenticatorData::class,
            $pluginData->getData()
        );
    }
}