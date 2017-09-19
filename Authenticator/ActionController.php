<?php
/**
 *  sysPass-Authenticator
 *
 * @author nuxsmin
 * @link http://syspass.org
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

namespace Plugins\Authenticator;

use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use SP\Controller\ItemControllerInterface;
use SP\Controller\RequestControllerTrait;
use SP\Core\Exceptions\SPException;
use SP\Core\Messages\LogMessage;
use SP\Core\Messages\NoticeMessage;
use SP\Core\Plugin\PluginDataStore;
use SP\Core\Session as CoreSession;
use SP\Core\SessionUtil;
use SP\Http\Request;
use SP\Log\Email;
use SP\Mgmt\Notices\Notice;
use SP\Util\ArrayUtil;
use SP\Util\Checks;
use SP\Util\Json;
use SP\Util\Util;

/**
 * Class ActionController
 *
 * @package Plugins\Authenticator
 */
class ActionController implements ItemControllerInterface
{
    const ACTION_TWOFA_SAVE = 1;
    const ACTION_TWOFA_CHECKCODE = 2;
    const ACTION_TWOFA_SHOWCODES = 3;
    const ACTION_PLUGIN_CHECKVERSION = 100;

    use RequestControllerTrait;

    /**
     * @var AuthenticatorPlugin
     */
    protected $Plugin;

    /**
     * ActionController constructor.
     *
     * @throws \SP\Core\Exceptions\SPException
     */
    public function __construct()
    {
        $this->Plugin = new AuthenticatorPlugin();

        PluginDataStore::load($this->Plugin);

        $this->init();
    }

    /**
     * Realizar la acción solicitada en la la petición HTTP
     *
     * @throws \InvalidArgumentException
     * @throws \SP\Core\Exceptions\SPException
     */
    public function doAction()
    {
        try {
            switch ($this->actionId) {
                case self::ACTION_TWOFA_SAVE:
                    $this->save();
                    break;
                case self::ACTION_TWOFA_CHECKCODE:
                    $this->checkCode();
                    break;
                case self::ACTION_TWOFA_SHOWCODES:
                    $this->showRecoveryCodes();
                    break;
                case self::ACTION_PLUGIN_CHECKVERSION:
                    $this->checkVersion();
                    break;
                default:
                    $this->invalidAction();
            }
        } catch (\Exception $e) {
            $this->JsonResponse->setDescription($e->getMessage());
            Json::returnJson($this->JsonResponse);
        }
    }

    /**
     * Guardar los datos del plugin
     *
     * @throws \SP\Core\Exceptions\SPException
     * @throws \InvalidArgumentException
     * @throws \SP\Core\Exceptions\InvalidClassException
     */
    protected function save()
    {
        $pin = Request::analyze('security_pin');
        $twofa_enabled = Request::analyze('security_2faenabled', 0, false, 1);

        $AuthenticatorData = Session::getUserData();

        $twoFa = new Authenticator($this->itemId, CoreSession::getUserData()->getUserLogin(), $AuthenticatorData->getIV());

        if (!$twoFa->verifyKey($pin)
            && !(strlen($pin) === 20 && $this->useRecoveryCode($AuthenticatorData, $pin))) {
            $this->returnResponseError();
        }

        if (Checks::demoIsEnabled()) {
            $this->JsonResponse->setDescription(_t('authenticator', 'Ey, esto es una DEMO!!'));
            Json::returnJson($this->JsonResponse);
        }

        if ($twofa_enabled) {
            /** @var AuthenticatorData $AuthenticatorData */
            $AuthenticatorData->setUserId($this->itemId);
            $AuthenticatorData->setTwofaEnabled($twofa_enabled);
            $AuthenticatorData->setExpireDays(Request::analyze('expiredays', 0));
            $AuthenticatorData->setDate(time());

            try {
                $AuthenticatorData->setRecoveryCodes($this->generateRecoveryCodes());
            } catch (EnvironmentIsBrokenException $e) {
                debugLog($e->getMessage());
            }

            $this->Plugin->setDataForId($this->itemId, $AuthenticatorData);

            if ($this->savePluginUserData($AuthenticatorData)) {
                $this->JsonResponse->addMessage(_t('authenticator', '2FA Habilitado'));
            }
        } elseif (!$twofa_enabled) {
            if ($this->deletePluginUserData($this->itemId)) {
                $this->JsonResponse->addMessage(_t('authenticator', '2FA Deshabilitado'));
            }
        }

        $this->JsonResponse->setStatus(0);
        $this->JsonResponse->setDescription(_t('authenticator', 'Preferencias actualizadas'));

        Json::returnJson($this->JsonResponse);
    }

    /**
     * Usar un código de recuperación y deshabilitar 2FA
     *
     * @param AuthenticatorData $AuthenticatorData
     * @param                   $code
     * @return bool|string
     */
    protected function useRecoveryCode(AuthenticatorData $AuthenticatorData, $code)
    {
        $codes = $AuthenticatorData->getRecoveryCodes();
        $key = array_search($code, $codes, true);

        if ($key !== false) {

            unset($codes[$key]);

            // Reindexar el array...
            if (count($codes) > 0) {
                $AuthenticatorData->setRecoveryCodes(array_values($codes));
            } else {
                $AuthenticatorData->setRecoveryCodes([]);
            }

            $AuthenticatorData->setLastRecoveryTime(time());

            return $this->savePluginUserData($AuthenticatorData);
        }

        return false;
    }

    /**
     * Guardar datos del Plugin de un usuario
     *
     * @param AuthenticatorData $AuthenticatorData
     * @return bool
     */
    protected function savePluginUserData(AuthenticatorData $AuthenticatorData)
    {
        try {
            $this->Plugin->setDataForId($AuthenticatorData->getUserId(), $AuthenticatorData);
            PluginDataStore::save($this->Plugin);
        } catch (SPException $e) {
            return false;
        }

        return true;
    }

    /**
     * Autentificación incorrecta
     * @param bool $isAuth
     */
    protected function returnResponseError($isAuth = false)
    {
        if ($isAuth === true) {
            Session::setTwoFApass(false);
            CoreSession::setAuthCompleted(false);
        }

        $this->JsonResponse->setDescription(_t('authenticator', 'Código incorrecto'));

        Json::returnJson($this->JsonResponse);
    }

    /**
     * Generar códigos de recuperación
     *
     * @return array
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    protected function generateRecoveryCodes()
    {
        $codes = [];
        $i = 1;

        do {
            $codes[] = Util::generateRandomBytes(10);
            $i++;
        } while ($i <= 10);

        return $codes;
    }

    /**
     * Eliminar los datos del Plugin de un usuario
     *
     * @param $id
     * @return bool
     * @internal param AuthenticatorData $AuthenticatorData
     */
    protected function deletePluginUserData($id)
    {
        try {
            $this->Plugin->deleteDataForId($id);

            PluginDataStore::save($this->Plugin);
        } catch (SPException $e) {
            return false;
        }

        return true;
    }

    /**
     * Comprobar el código 2FA
     *
     * @throws \InvalidArgumentException
     * @throws \SP\Core\Exceptions\SPException
     */
    protected function checkCode()
    {
        $userId = Request::analyze('itemId', 0);
        $pin = Request::analyze('security_pin');
        $codeReset = Request::analyze('code_reset', false, false, true);

        // Buscar al usuario en los datos del plugin
        /** @var AuthenticatorData $AuthenticatorData */
        $AuthenticatorData = ArrayUtil::searchInObject($this->Plugin->getData(), 'userId', $userId);

        if ($AuthenticatorData === null) {
            $this->returnResponseError(true);
        }

        if (strlen($pin) === 20 && $this->useRecoveryCode($AuthenticatorData, $pin)) {
            $Message = new NoticeMessage();
            $Message->addDescription(_t('authenticator', 'Código de recuperación utilizado'));

            $NoticeData = Notice::getItem()->getItemData();
            $NoticeData->setNoticeComponent($this->Plugin->getName());
            $NoticeData->setNoticeUserId($AuthenticatorData->getUserId());
            $NoticeData->setNoticeType(_t('authenticator', 'Preferencias'));
            $NoticeData->setNoticeDescription($Message);

            Notice::getItem($NoticeData)->add();

            $this->returnResponseOk(true);
        }

        if ($codeReset && $this->sendResetEmail($AuthenticatorData)) {
            Session::setTwoFApass(false);
            CoreSession::setAuthCompleted(false);

            $this->JsonResponse->setDescription(_t('authenticator', 'Email de recuperación enviado'));
            $this->JsonResponse->setStatus(0);

            Json::returnJson($this->JsonResponse);
        }

        $TwoFa = new Authenticator($userId, CoreSession::getUserData()->getUserLogin(), $AuthenticatorData->getIV());

        if ($pin && $TwoFa->verifyKey($pin)) {
            $this->returnResponseOk(true);
        } else {
            $this->returnResponseError();
        }
    }

    /**
     * Autentificación correcta
     *
     * @param bool $isAuth
     */
    protected function returnResponseOk($isAuth = false)
    {
        if ($isAuth === true) {
            Session::setTwoFApass(true);
            CoreSession::setAuthCompleted(true);
        }

        $this->JsonResponse->setDescription(_t('authenticator', 'Código correcto'));
        $this->JsonResponse->setStatus(0);

        Json::returnJson($this->JsonResponse);
    }

    /**
     * Envial email con código de recuperación
     *
     * @param AuthenticatorData $AuthenticatorData
     * @return bool
     */
    protected function sendResetEmail(AuthenticatorData $AuthenticatorData)
    {
        $email = CoreSession::getUserData()->getUserEmail();

        if (!empty($email)) {

            $code = $this->pickRecoveryCode($AuthenticatorData);

            if ($code !== false) {
                $LogMessage = new LogMessage();
                $LogMessage->setAction(_t('authenticator', 'Recuperación de Código 2FA'));
                $LogMessage->addDescriptionHtml(_t('authenticator', 'Se ha solicitado un código de recuperación para 2FA.'));
                $LogMessage->addDescriptionLine();
                $LogMessage->addDescription(sprintf(_t('authenticator', 'El código de recuperación es: %s'), $code));

                return Email::sendEmail($LogMessage, $email);
            }
        }

        return false;
    }

    /**
     * Devolver un código de recuperación
     *
     * @param AuthenticatorData $AuthenticatorData
     * @return mixed
     */
    protected function pickRecoveryCode(AuthenticatorData $AuthenticatorData)
    {
        $recoveryTime = $AuthenticatorData->getLastRecoveryTime();
        $codes = $AuthenticatorData->getRecoveryCodes();
        $numCodes = count($codes);

        if ($recoveryTime === 0
            || (time() - $recoveryTime >= AuthenticatorPlugin::RECOVERY_GRACE_TIME && $numCodes === 0)
        ) {
            try {
                $codes = $this->generateRecoveryCodes();
            } catch (EnvironmentIsBrokenException $e) {
                debugLog($e->getMessage());

                return false;
            }

            $AuthenticatorData->setRecoveryCodes($codes);
            $AuthenticatorData->setLastRecoveryTime(time());

            if ($this->savePluginUserData($AuthenticatorData) === false) {
                return false;
            }
        }

        if ($numCodes > 0) {
            return $codes[$numCodes - 1];
        }

        return false;
    }

    /**
     * Mostrar códigos de recuperación
     * @throws \SP\Core\Exceptions\SPException
     */
    protected function showRecoveryCodes()
    {
        $AuthenticatorData = Session::getUserData();
        $codes = $AuthenticatorData->getRecoveryCodes();

        if (count($codes) > 0) {
            $Message = new NoticeMessage();
            $Message->addDescription(_t('authenticator', 'Códigos de recuperación visualizados'));

            $NoticeData = Notice::getItem()->getItemData();
            $NoticeData->setNoticeComponent($this->Plugin->getName());
            $NoticeData->setNoticeUserId($AuthenticatorData->getUserId());
            $NoticeData->setNoticeType(_t('authenticator', 'Preferencias'));
            $NoticeData->setNoticeDescription($Message);

            Notice::getItem($NoticeData)->add();

            $this->JsonResponse->setData($codes);
            $this->JsonResponse->setStatus(0);
        } else {
            $this->JsonResponse->setDescription(_t('authenticator', 'Códigos de recuperación agotados'));
            $this->JsonResponse->setStatus(1);
        }

        Json::returnJson($this->JsonResponse);
    }

    /**
     * Comprobar la versión del plugin
     *
     * @throws \SP\Core\Exceptions\SPException
     */
    protected function checkVersion()
    {
        $data = json_decode(Util::getDataFromUrl(AuthenticatorPlugin::VERSION_URL));
        $pluginName = $this->Plugin->getName();

        if (isset($data->{$pluginName})) {
            $out = new \stdClass();
            $out->plugin = $pluginName;
            $out->remoteVersion = $data->{$pluginName}->version;
            $out->localVersion = implode('.', $this->Plugin->getVersion());

            if (version_compare($out->remoteVersion, $out->localVersion) === 1) {
                $this->JsonResponse->setData($out);
            }

            $this->JsonResponse->setStatus(0);

            Json::returnJson($this->JsonResponse);
        }
    }

    /**
     * Comprobaciones antes de realizar una acción
     */
    protected function preActionChecks()
    {
        if (!$this->actionId
            || ($this->actionId !== self::ACTION_PLUGIN_CHECKVERSION
                && (!$this->sk || !SessionUtil::checkSessionKey($this->sk)))
        ) {
            $this->invalidAction();
        }
    }
}