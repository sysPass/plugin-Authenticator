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

namespace SP\Modules\Web\Plugins\Authenticator\Services;

use BaconQrCode\Renderer\Image\Png;
use BaconQrCode\Writer;
use Base2n;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use SP\Core\Exceptions\CheckException;
use SP\Core\PhpExtensionChecker;
use SP\Modules\Web\Plugins\Authenticator\Models\AuthenticatorData;
use SP\Modules\Web\Plugins\Authenticator\Plugin;
use SP\Modules\Web\Plugins\Authenticator\Util\Google2FA;
use SP\Plugin\PluginManager;
use SP\Services\Service;
use SP\Util\PasswordUtil;

defined('APP_ROOT') || die();

/**
 * Class AuthenticatorService
 *
 * @package SP\Auth
 */
final class AuthenticatorService extends Service
{
    /**
     * @var Plugin
     */
    private $plugin;
    /**
     * @var PhpExtensionChecker
     */
    private $extensionChecker;

    /**
     * Generar una clave de inicialización codificada en Base32
     *
     * @return string
     * @throws EnvironmentIsBrokenException
     */
    public static function makeInitializationKey()
    {
        $iv = PasswordUtil::generateRandomBytes(32);

        $base32 = new Base2n(
            5,
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
            false,
            true,
            true
        );

        return substr($base32->encode($iv), 0, 16);
    }

    /**
     * Verificar el código de 2FA
     *
     * @param string $key
     * @param string $iv
     *
     * @return bool
     * @throws \Exception
     */
    public static function verifyKey(string $key, string $iv)
    {
        return Google2FA::verify_key($iv, $key);
    }

    /**
     * Comprobar el token del usuario
     *
     * @param string $userToken EL código del usuario
     * @param string $iv
     *
     * @return bool
     * @throws \Exception
     */
    public static function checkUserToken(string $userToken, string $iv)
    {
        $totp = Google2FA::oath_totp(
            Google2FA::base32_decode($iv),
            Google2FA::get_timestamp()
        );

        return $totp === $userToken;
    }

    /**
     * getQrCode
     *
     * @param string $login
     * @param string $iv
     *
     * @return bool
     */
    public function getQrCodeFromUrl(string $login, string $iv)
    {
        try {
            $this->extensionChecker->checkCurlAvailable(true);

            $request = $this->dic->get(Client::class)
                ->request('GET', $this->getUserQRUrl($login, $iv));

            logger($request->getHeaderLine('content-type'));

            if ($request->getStatusCode() === 200
                && strpos($request->getHeaderLine('content-type'), 'image/png') !== false
            ) {
                return base64_encode($request->getBody());
            }
        } catch (GuzzleException $e) {
            processException($e);
        } catch (CheckException $e) {
            processException($e);
        }

        return false;
    }

    /**
     * Devolver la cadena con la URL para solicitar el código QR
     *
     * @param string $login
     * @param string $iv
     *
     * @return string
     */
    public function getUserQRUrl(string $login, string $iv)
    {
        $qrUrl = 'https://www.google.com/chart?chs=150x150&chld=M|0&cht=qr&chl=';
        $qrUrl .= urlencode('otpauth://totp/sysPass:syspass/' . $login . '?secret=' . $iv . '&issuer=sysPass');

        return $qrUrl;
    }

    /**
     * getQrCode
     *
     * @param string $login
     * @param string $iv
     *
     * @return string
     */
    public function getQrCodeFromServer(string $login, string $iv)
    {
        $renderer = new Png();
        $renderer->setHeight(200);
        $renderer->setWidth(200);

        $writer = new Writer($renderer);
        return base64_encode($writer->writeString('otpauth://totp/sysPass:syspass/' . $login . '?secret=' . $iv . '&issuer=sysPass'));
    }

    /**
     * Devolver un código de recuperación
     *
     * @param AuthenticatorData $authenticatorData
     *
     * @return string
     * @throws AuthenticatorException
     * @throws EnvironmentIsBrokenException
     * @throws \SP\Core\Exceptions\ConstraintException
     * @throws \SP\Core\Exceptions\QueryException
     * @throws \SP\Repositories\NoSuchItemException
     */
    public function pickRecoveryCode(AuthenticatorData $authenticatorData)
    {
        $recoveryTime = $authenticatorData->getLastRecoveryTime();
        $codes = $authenticatorData->getRecoveryCodes();
        $numCodes = count($codes);

        if ($numCodes > 0) {
            $code = array_pop($codes);

            $this->saveRecoveryCodes($codes, $authenticatorData);

            return $code;
        }

        if ($recoveryTime === 0
            || (time() - $recoveryTime >= Plugin::RECOVERY_GRACE_TIME
                && $numCodes === 0)
        ) {
            $codes = $this->generateRecoveryCodes();

            $code = array_pop($codes);

            $this->saveRecoveryCodes($codes, $authenticatorData);

            return $code;
        }

        throw new AuthenticatorException(_t('authenticator', 'There aren\'t any recovery codes available'));
    }

    /**
     * @param                   $codes
     * @param AuthenticatorData $authenticatorData
     *
     * @throws \SP\Core\Exceptions\ConstraintException
     * @throws \SP\Core\Exceptions\QueryException
     * @throws \SP\Repositories\NoSuchItemException
     */
    private function saveRecoveryCodes(array $codes, AuthenticatorData $authenticatorData)
    {
        $authenticatorData->setRecoveryCodes($codes);
        $authenticatorData->setLastRecoveryTime(time());
        $this->savePluginUserData($authenticatorData);
    }

    /**
     * Guardar datos del Plugin de un usuario
     *
     * @param AuthenticatorData $authenticatorData
     *
     * @return void
     * @throws \SP\Core\Exceptions\ConstraintException
     * @throws \SP\Core\Exceptions\QueryException
     * @throws \SP\Repositories\NoSuchItemException
     */
    public function savePluginUserData(AuthenticatorData $authenticatorData)
    {
        $this->plugin->setDataForId($authenticatorData->getUserId(), $authenticatorData);
        $this->plugin->saveData();
    }

    /**
     * Generar códigos de recuperación
     *
     * @return array
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    public function generateRecoveryCodes()
    {
        $codes = [];
        $i = 1;

        do {
            $codes[] = PasswordUtil::generateRandomBytes(10);
            $i++;
        } while ($i <= 10);

        return $codes;
    }

    /**
     * Eliminar los datos del Plugin de un usuario
     *
     * @param $id
     *
     * @return void
     * @throws \SP\Core\Exceptions\ConstraintException
     * @throws \SP\Core\Exceptions\QueryException
     * @throws \SP\Repositories\NoSuchItemException
     * @internal param AuthenticatorData $AuthenticatorData
     */
    public function deletePluginUserData($id)
    {
        $this->plugin->deleteDataForId($id);
        $this->plugin->saveData();
    }

    /**
     * Comprobar la versión del plugin
     */
    public function checkVersion()
    {
        try {
            $this->extensionChecker->checkCurlAvailable(true);

            $request = $this->dic->get(Client::class)
                ->request('GET', Plugin::VERSION_URL);

            if ($request->getStatusCode() === 200
                && strpos($request->getHeaderLine('content-type'), 'application/json') !== false
            ) {
                $data = $request->getBody();

                if (isset($data->{$pluginName})) {
                    $out = new \stdClass();
                    $out->plugin = $pluginName;
                    $out->remoteVersion = $data->{$pluginName}->version;
                    $out->localVersion = implode('.', $this->plugin->getVersion());
                    $out->result = version_compare($out->remoteVersion, $out->localVersion) === 1;

                    return $out;
                }
            }
        } catch (GuzzleException $e) {
            processException($e);
        } catch (CheckException $e) {
            processException($e);
        }

        return false;
    }

    /**
     * Usar un código de recuperación y deshabilitar 2FA
     *
     * @param AuthenticatorData $authenticatorData
     * @param string            $code
     *
     * @return bool
     * @throws \SP\Core\Exceptions\ConstraintException
     * @throws \SP\Core\Exceptions\QueryException
     * @throws \SP\Repositories\NoSuchItemException
     */
    public function useRecoveryCode(AuthenticatorData $authenticatorData, $code)
    {
        $codes = $authenticatorData->getRecoveryCodes();
        $usedKey = array_search($code, $codes, true);

        if ($usedKey !== false) {
            $this->saveRecoveryCodes(array_values(array_filter($codes, function ($key) use ($usedKey) {
                return $key !== $usedKey;
            }, ARRAY_FILTER_USE_KEY)), $authenticatorData);

            return true;
        }

        return false;
    }

    protected function initialize()
    {
        $this->extensionChecker = $this->dic->get(PhpExtensionChecker::class);
        $this->plugin = $this->dic->get(PluginManager::class)
            ->getPluginInfo(Plugin::PLUGIN_NAME);
    }
}