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
use SP\Core\Messages\MailMessage;
use SP\Http\JsonResponse;
use SP\Modules\Web\Controllers\Traits\JsonTrait;
use SP\Modules\Web\Plugins\Authenticator\Models\AuthenticatorData;
use SP\Modules\Web\Plugins\Authenticator\Plugin;
use SP\Modules\Web\Plugins\Authenticator\Services\AuthenticatorException;
use SP\Modules\Web\Plugins\Authenticator\Services\AuthenticatorService;
use SP\Modules\Web\Plugins\Authenticator\Util\PluginContext;
use SP\Plugin\PluginManager;
use SP\Repositories\Track\TrackRequest;
use SP\Services\Mail\MailService;
use SP\Services\Track\TrackService;
use SP\Services\User\UserLoginResponse;
use SP\Util\ArrayUtil;

/**
 * Class ActionController
 *
 * @package Plugins\Authenticator
 */
final class AuthenticatorController extends SimpleControllerBase
{
    use JsonTrait;

    /**
     * @var TrackRequest
     */
    private $trackRequest;
    /**
     * @var TrackService
     */
    private $trackService;
    /**
     * @var UserLoginResponse
     */
    private $userData;
    /**
     * @var AuthenticatorService
     */
    private $authenticatorService;
    /**
     * @var PluginContext
     */
    private $pluginContext;
    /**
     * @var Plugin
     */
    private $plugin;

    /**
     * Guardar los datos del plugin
     */
    public function saveAction()
    {
        try {
            $pin = $this->request->analyzeString('pin');

            $authenticatorData = $this->pluginContext->getUserData();

            if ($authenticatorData === null) {
                $authenticatorData = new AuthenticatorData();
                $authenticatorData->setIV(AuthenticatorService::makeInitializationKey());
            }

            if ($this->configData->isDemoEnabled()) {
                return $this->returnJsonResponse(
                    JsonResponse::JSON_WARNING,
                    _t('authenticator', 'Ey, esto es una DEMO!!')
                );
            }

            if ($this->trackService->checkTracking($this->trackRequest)) {
                $this->addTracking();

                throw new AuthenticatorException(__u('Intentos excedidos'));
            }

            if ($this->checkRecoveryCode($pin, $authenticatorData)
                || $this->checkPin($pin, $authenticatorData)
            ) {
                return $this->save2FAStatus($authenticatorData);
            }

            $this->addTracking();

            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                _t('authenticator', 'Código incorrecto')
            );
        } catch (AuthenticatorException $e) {
            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                $e->getMessage()
            );
        } catch (\Exception $e) {
            processException($e);

            $this->eventDispatcher->notifyEvent('exception', new Event($e));

            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                __u('Error interno'),
                [__u($e->getMessage())]
            );
        }
    }

    /**
     * Añadir un seguimiento
     */
    private function addTracking()
    {
        try {
            $this->trackService->add($this->trackRequest);
        } catch (\Exception $e) {
            processException($e);
        }
    }

    /**
     * @param string            $pin
     * @param AuthenticatorData $authenticatorData
     *
     * @return bool
     * @throws \Exception
     */
    private function checkRecoveryCode($pin, AuthenticatorData $authenticatorData)
    {
        if (strlen($pin) === 20
            && $this->authenticatorService->useRecoveryCode($authenticatorData, $pin)
        ) {
            $this->eventDispatcher->notifyEvent('authenticator.use.recoverycode',
                new Event($this, EventMessage::factory()
                    ->addDescription(_t('authenticator', 'Código de recuperación utilizado')))
            );

            return true;
        }

        return false;
    }

    /**
     * @param string            $pin
     * @param AuthenticatorData $authenticatorData
     *
     * @return bool
     * @throws \Exception
     */
    private function checkPin($pin, AuthenticatorData $authenticatorData)
    {
        if (empty($pin)
            || AuthenticatorService::verifyKey($pin, $authenticatorData->getIV()) === false
        ) {
            $this->addTracking();

            return false;
        }

        return true;
    }

    /**
     * Enables or disables 2FA
     *
     * @param AuthenticatorData $authenticatorData
     *
     * @return bool
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \SP\Core\Exceptions\ConstraintException
     * @throws \SP\Core\Exceptions\QueryException
     * @throws \SP\Repositories\NoSuchItemException
     */
    private function save2FAStatus(AuthenticatorData $authenticatorData)
    {
        $enable = $this->request->analyzeBool('2faenabled', false);

        if ($authenticatorData->isTwofaEnabled() === false
            && $enable === true
        ) {
            $authenticatorData->setUserId($this->userData->getId());
            $authenticatorData->setTwofaEnabled(true);
            $authenticatorData->setExpireDays($this->request->analyzeInt('expiredays', 0));
            $authenticatorData->setDate(time());
            $authenticatorData->setRecoveryCodes($this->authenticatorService->generateRecoveryCodes());

            $this->plugin->setDataForId($this->userData->getId(), $authenticatorData);

            $this->authenticatorService->savePluginUserData($authenticatorData);

            return $this->returnJsonResponse(
                JsonResponse::JSON_SUCCESS,
                _t('authenticator', '2FA Habilitado')
            );
        }

        if ($authenticatorData->isTwofaEnabled() === true
            && $enable === false
        ) {
            $this->authenticatorService->deletePluginUserData($this->userData->getId());

            return $this->returnJsonResponse(
                JsonResponse::JSON_SUCCESS,
                _t('authenticator', '2FA Deshabilitado')
            );
        }

        return $this->returnJsonResponse(
            JsonResponse::JSON_SUCCESS,
            __u('Sin cambios')
        );
    }

    /**
     * Comprobar el código 2FA
     */
    public function checkCodeAction()
    {
        try {
            $pin = $this->request->analyzeString('pin');
            $codeReset = $this->request->analyzeBool('code_reset', false);

            // Buscar al usuario en los datos del plugin
            /** @var AuthenticatorData $authenticatorData */
            $authenticatorData = ArrayUtil::searchInObject(
                $this->plugin->getData(),
                'userId',
                $this->userData->getId()
            );

            if ($authenticatorData === null) {
                $this->pluginContext->setTwoFApass(false);
                $this->session->setAuthCompleted(false);

                throw new AuthenticatorException(__u('Usuario no encontrado'));
            }

            if ($codeReset
                && $this->sendResetEmail($authenticatorData)
            ) {
                $this->addTracking();

                $this->pluginContext->setTwoFApass(false);
                $this->session->setAuthCompleted(false);

                return $this->returnJsonResponse(
                    JsonResponse::JSON_SUCCESS,
                    _t('authenticator', 'Email de recuperación enviado')
                );
            }

            if ($this->checkRecoveryCode($pin, $authenticatorData)
                || $this->checkPin($pin, $authenticatorData)
            ) {
                $this->pluginContext->setTwoFApass(true);
                $this->session->setAuthCompleted(true);

                // Use deep link if set
                $url = 'index.php?r=' . ($this->getSignedUriFromRequest() ?: 'index');

                return $this->returnJsonResponseData(
                    ['url' => $url],
                    JsonResponse::JSON_SUCCESS,
                    _t('authenticator', 'Código correcto')
                );
            }

            $this->addTracking();

            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                _t('authenticator', 'Código incorrecto')
            );
        } catch (AuthenticatorException $e) {
            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                $e->getMessage()
            );
        } catch (\Exception $e) {
            processException($e);

            $this->eventDispatcher->notifyEvent('exception', new Event($e));

            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                __u('Error interno')
            );
        }
    }

    /**
     * Sends an email including the recovery code
     *
     * @param AuthenticatorData $authenticatorData
     *
     * @return bool
     * @throws AuthenticatorException
     */
    private function sendResetEmail(AuthenticatorData $authenticatorData)
    {
        try {
            if (!empty($this->userData->getEmail())) {
                $code = $this->authenticatorService->pickRecoveryCode($authenticatorData);

                $message = new MailMessage();
                $message->setTitle(_t('authenticator', 'Recuperación de Código 2FA'));
                $message->addDescription(_t('authenticator', 'Se ha solicitado un código de recuperación para 2FA.'));
                $message->addDescriptionLine();
                $message->addDescription(sprintf(_t('authenticator', 'El código de recuperación es: %s'), $code));

                $this->dic->get(MailService::class)
                    ->send(_t('authenticator', 'Recuperación de Código 2FA'),
                        $this->userData->getEmail(),
                        $message);

                return true;
            }

            return false;
        } catch (\Exception $e) {
            processException($e);

            $this->eventDispatcher->notifyEvent('exception', new Event($e));

            throw new AuthenticatorException(__u('Error al enviar correo'));
        }
    }

    /**
     * Mostrar códigos de recuperación
     */
    public function showRecoveryCodesAction()
    {
        try {
            $authenticatorData = $this->plugin->getDataForId($this->userData->getId());

            if ($authenticatorData === null) {
                throw new AuthenticatorException(__u('Usuario no encontrado'));
            }

            $codes = $authenticatorData->getRecoveryCodes();

            if (count($codes) > 0) {
                $this->eventDispatcher->notifyEvent('authenticator.show.recoverycode',
                    new Event($this, EventMessage::factory()
                        ->addDescription(_t('authenticator', 'Códigos de recuperación visualizados')))
                );

                return $this->returnJsonResponseData($codes);
            } else {
                return $this->returnJsonResponse(
                    JsonResponse::JSON_ERROR,
                    _t('authenticator', 'Códigos de recuperación agotados')
                );
            }
        } catch (\Exception $e) {
            processException($e);

            $this->eventDispatcher->notifyEvent('exception', new Event($e));

            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                __u('Error interno')
            );
        }
    }

    /**
     * @return bool
     */
    public function checkVersionAction()
    {
        return $this->returnJsonResponseData($this->authenticatorService->checkVersion());
    }

    /**
     * @throws \DI\DependencyException
     * @throws \DI\NotFoundException
     * @throws \SP\Core\Exceptions\InvalidArgumentException
     */
    protected function initialize()
    {
        $this->authenticatorService = $this->dic->get(AuthenticatorService::class);
        $this->pluginContext = $this->dic->get(PluginContext::class);
        $this->trackService = $this->dic->get(TrackService::class);
        $this->plugin = $this->dic->get(PluginManager::class)
            ->getPluginInfo(Plugin::PLUGIN_NAME);
        $this->userData = $this->session->getUserData();
        $this->trackRequest = $this->trackService->getTrackRequest(__CLASS__);
    }
}