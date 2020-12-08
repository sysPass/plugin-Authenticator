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

use Defuse\Crypto\Exception\CryptoException;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use DI\DependencyException;
use DI\NotFoundException;
use Exception;
use SP\Core\Events\Event;
use SP\Core\Events\EventMessage;
use SP\Core\Exceptions\ConstraintException;
use SP\Core\Exceptions\InvalidArgumentException;
use SP\Core\Exceptions\NoSuchPropertyException;
use SP\Core\Exceptions\QueryException;
use SP\Core\Messages\MailMessage;
use SP\Http\JsonResponse;
use SP\Modules\Web\Controllers\Traits\JsonTrait;
use SP\Modules\Web\Plugins\Authenticator\Models\AuthenticatorData;
use SP\Modules\Web\Plugins\Authenticator\Plugin;
use SP\Modules\Web\Plugins\Authenticator\Services\AuthenticatorException;
use SP\Modules\Web\Plugins\Authenticator\Services\AuthenticatorService;
use SP\Modules\Web\Plugins\Authenticator\Util\PluginContext;
use SP\Plugin\PluginManager;
use SP\Repositories\NoSuchItemException;
use SP\Repositories\Track\TrackRequest;
use SP\Services\Mail\MailService;
use SP\Services\ServiceException;
use SP\Services\Track\TrackService;
use SP\Services\User\UserLoginResponse;

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
     * Save plugin's data
     */
    public function saveAction(): bool
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
                    _t('authenticator', 'Ey, this is a DEMO!!')
                );
            }

            if ($this->trackService->checkTracking($this->trackRequest)) {
                $this->addTracking();

                throw new AuthenticatorException(__u('Attempts exceeded'));
            }

            if ($this->checkRecoveryCode($pin, $authenticatorData)
                || $this->checkPin($pin, $authenticatorData)
            ) {
                return $this->save2FAStatus($authenticatorData);
            }

            $this->addTracking();

            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                _t('authenticator', 'Wrong code')
            );
        } catch (AuthenticatorException $e) {
            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                $e->getMessage()
            );
        } catch (Exception $e) {
            processException($e);

            $this->eventDispatcher->notifyEvent('exception', new Event($e));

            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                __u('Internal error'),
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
        } catch (Exception $e) {
            processException($e);
        }
    }

    /**
     * @param string            $pin
     * @param AuthenticatorData $authenticatorData
     *
     * @return bool
     * @throws Exception
     */
    private function checkRecoveryCode(string $pin, AuthenticatorData $authenticatorData): bool
    {
        if (strlen($pin) === 20
            && $this->authenticatorService->useRecoveryCode($authenticatorData, $pin)
        ) {
            $this->eventDispatcher->notifyEvent('authenticator.use.recoverycode',
                new Event($this, EventMessage::factory()
                    ->addDescription(_t('authenticator', 'Recovery code used')))
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
     * @throws Exception
     */
    private function checkPin(string $pin, AuthenticatorData $authenticatorData): bool
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
     * @throws CryptoException
     * @throws EnvironmentIsBrokenException
     * @throws ConstraintException
     * @throws NoSuchPropertyException
     * @throws QueryException
     * @throws NoSuchItemException
     * @throws ServiceException
     */
    private function save2FAStatus(AuthenticatorData $authenticatorData): bool
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

            $this->plugin->saveData($this->userData->getId(), $authenticatorData);

            $this->eventDispatcher->notifyEvent('authenticator.edit.enable',
                new Event($this, EventMessage::factory()
                    ->addDescription(_t('authenticator', '2FA Enabled'))
                    ->addDetail(__('User'), $this->userData->getLogin())
                    ->addExtra('userId', $this->userData->getId())
                    ->addExtra('expireDays', $authenticatorData->getExpireDays())
                )
            );

            return $this->returnJsonResponse(
                JsonResponse::JSON_SUCCESS,
                _t('authenticator', '2FA Enabled')
            );
        }

        if ($authenticatorData->isTwofaEnabled() === true
            && $enable === false
        ) {
            $this->authenticatorService->deletePluginUserData($this->userData->getId());

            $this->eventDispatcher->notifyEvent('authenticator.edit.disable',
                new Event($this, EventMessage::factory()
                    ->addDescription(_t('authenticator', '2FA Disabled'))
                    ->addDetail(__('User'), $this->userData->getLogin())
                    ->addExtra('userId', $this->userData->getId())
                )
            );

            return $this->returnJsonResponse(
                JsonResponse::JSON_SUCCESS,
                _t('authenticator', '2FA Disabled')
            );
        }

        return $this->returnJsonResponse(
            JsonResponse::JSON_SUCCESS,
            __u('No changes')
        );
    }

    /**
     * Comprobar el código 2FA
     */
    public function checkCodeAction(): bool
    {
        try {
            $pin = $this->request->analyzeString('pin');
            $codeReset = $this->request->analyzeBool('code_reset', false);

            $authenticatorData = $this->plugin->getData();

            if ($authenticatorData === false) {
                $this->pluginContext->setTwoFApass(false);
                $this->session->setAuthCompleted(false);

                throw new AuthenticatorException(__u('User not found'));
            }

            if ($codeReset
                && $this->sendResetEmail($authenticatorData)
            ) {
                $this->addTracking();

                $this->pluginContext->setTwoFApass(false);
                $this->session->setAuthCompleted(false);

                return $this->returnJsonResponse(
                    JsonResponse::JSON_SUCCESS,
                    _t('authenticator', 'Recovery email has been sent')
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
                    _t('authenticator', 'Correct code')
                );
            }

            $this->addTracking();

            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                _t('authenticator', 'Wrong code')
            );
        } catch (AuthenticatorException $e) {
            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                $e->getMessage()
            );
        } catch (Exception $e) {
            processException($e);

            $this->eventDispatcher->notifyEvent('exception', new Event($e));

            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                __u('Internal error')
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
    private function sendResetEmail(AuthenticatorData $authenticatorData): bool
    {
        try {
            if (!empty($this->userData->getEmail())) {
                $code = $this->authenticatorService->pickRecoveryCode($authenticatorData);

                $message = new MailMessage();
                $message->setTitle(_t('authenticator', '2FA Code Recovery'));
                $message->addDescription(_t('authenticator', 'A 2FA recovery code has been requested.'));
                $message->addDescriptionLine();
                $message->addDescription(sprintf(_t('authenticator', 'The recovery code is: %s'), $code));

                $this->dic->get(MailService::class)
                    ->send(_t('authenticator', '2FA Code Recovery'),
                        $this->userData->getEmail(),
                        $message);

                $this->eventDispatcher->notifyEvent('authenticator.send.recoverycode',
                    new Event($this, EventMessage::factory()
                        ->addDescription(_t('authenticator', '2FA Code Recovery'))
                        ->addDetail(__('User'), $this->userData->getLogin())
                        ->addExtra('userId', $this->userData->getId())
                    )
                );

                return true;
            }

            return false;
        } catch (AuthenticatorException $e) {
            throw $e;
        } catch (Exception $e) {
            processException($e);

            $this->eventDispatcher->notifyEvent('exception', new Event($e));

            throw new AuthenticatorException(__u('Error while sending the email'));
        }
    }

    /**
     * Mostrar códigos de recuperación
     */
    public function showRecoveryCodesAction(): bool
    {
        try {
            $authenticatorData = $this->plugin->getData();

            if ($authenticatorData === null) {
                throw new AuthenticatorException(__u('User not found'));
            }

            $codes = $authenticatorData->getRecoveryCodes();

            if (count($codes) > 0) {
                $this->eventDispatcher->notifyEvent('authenticator.show.recoverycode',
                    new Event($this, EventMessage::factory()
                        ->addDescription(_t('authenticator', 'Recovery codes displayed'))
                        ->addDetail(__('User'), $this->userData->getLogin())
                        ->addExtra('userId', $this->userData->getId())
                    )
                );

                return $this->returnJsonResponseData($codes);
            } else {
                return $this->returnJsonResponse(
                    JsonResponse::JSON_ERROR,
                    _t('authenticator', 'There aren\'t any recovery codes available')
                );
            }
        } catch (Exception $e) {
            processException($e);

            $this->eventDispatcher->notifyEvent('exception', new Event($e));

            return $this->returnJsonResponse(
                JsonResponse::JSON_ERROR,
                __u('Internal error')
            );
        }
    }

    /**
     * @return bool
     */
    public function checkVersionAction(): bool
    {
        return $this->returnJsonResponseData($this->authenticatorService->checkVersion());
    }

    /**
     * @throws DependencyException
     * @throws NotFoundException
     * @throws InvalidArgumentException
     */
    protected function initialize()
    {
        $this->authenticatorService = $this->dic->get(AuthenticatorService::class);
        $this->pluginContext = $this->dic->get(PluginContext::class);
        $this->trackService = $this->dic->get(TrackService::class);
        $this->userData = $this->session->getUserData();
        $this->trackRequest = $this->trackService->getTrackRequest(__CLASS__);

        $pluginManager = $this->dic->get(PluginManager::class);
        $this->plugin = $pluginManager->getPlugin(Plugin::PLUGIN_NAME, true);
    }
}