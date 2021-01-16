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

namespace SP\Modules\Web\Plugins\Authenticator\Services;

use BaconQrCode\Renderer\Image\Png;
use BaconQrCode\Writer;
use Base2n;
use Defuse\Crypto\Exception\CryptoException;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use SP\Core\Exceptions\CheckException;
use SP\Core\Exceptions\ConstraintException;
use SP\Core\Exceptions\NoSuchPropertyException;
use SP\Core\Exceptions\QueryException;
use SP\Core\PhpExtensionChecker;
use SP\Modules\Web\Plugins\Authenticator\Models\AuthenticatorData;
use SP\Modules\Web\Plugins\Authenticator\Plugin;
use SP\Modules\Web\Plugins\Authenticator\Util\Google2FA;
use SP\Plugin\PluginManager;
use SP\Repositories\NoSuchItemException;
use SP\Services\Service;
use SP\Services\ServiceException;
use SP\Util\PasswordUtil;
use stdClass;

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
    public static function makeInitializationKey(): string
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
     * @throws Exception
     */
    public static function verifyKey(string $key, string $iv): bool
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
     * @throws Exception
     */
    public static function checkUserToken(string $userToken, string $iv): bool
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
     * @throws CheckException
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
    public function getUserQRUrl(string $login, string $iv): string
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
    public function getQrCodeFromServer(string $login, string $iv): string
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
     */
    public function pickRecoveryCode(AuthenticatorData $authenticatorData): string
    {
        $recoveryTime = $authenticatorData->getLastRecoveryTime();
        $codes = $authenticatorData->getRecoveryCodes();
        $numCodes = count($codes);

        if ($numCodes > 0) {
            return $codes[0];
        }

        if ($recoveryTime === 0
            || (time() - $recoveryTime >= Plugin::RECOVERY_GRACE_TIME
                && $numCodes === 0)
        ) {
            $codes = $this->generateRecoveryCodes();

            return $codes[0];
        }

        throw new AuthenticatorException(_t('authenticator', 'There aren\'t any recovery codes available'));
    }

    /**
     * Generar códigos de recuperación
     *
     * @return array
     * @throws EnvironmentIsBrokenException
     */
    public function generateRecoveryCodes(): array
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
     * @param int $id
     *
     * @return void
     * @throws ConstraintException
     * @throws QueryException
     * @throws NoSuchItemException
     * @internal param AuthenticatorData $AuthenticatorData
     */
    public function deletePluginUserData(int $id)
    {
        $this->plugin->deleteDataForId($id);
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
                    $out = new stdClass();
                    $out->plugin = $pluginName;
                    $out->remoteVersion = $data->{$pluginName}->version;
                    $out->localVersion = implode('.', $this->plugin->getVersion());
                    $out->result = version_compare($out->remoteVersion, $out->localVersion) === 1;

                    return $out;
                }
            }
        } catch (GuzzleException $e) {
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
     * @throws CryptoException
     * @throws ConstraintException
     * @throws NoSuchPropertyException
     * @throws QueryException
     * @throws ServiceException
     */
    public function useRecoveryCode(AuthenticatorData $authenticatorData, string $code): bool
    {
        $codes = $authenticatorData->getRecoveryCodes();
        $usedKey = array_search($code, $codes, true);

        if ($usedKey !== false) {
            $this->saveRecoveryCodes(
                array_values(
                    array_filter($codes,
                        function ($key) use ($usedKey) {
                            return $key !== $usedKey;
                        }, ARRAY_FILTER_USE_KEY)
                ),
                $authenticatorData);

            return true;
        }

        return false;
    }

    /**
     * @param array             $codes
     * @param AuthenticatorData $authenticatorData
     *
     * @throws CryptoException
     * @throws ConstraintException
     * @throws NoSuchPropertyException
     * @throws QueryException
     * @throws ServiceException
     */
    private function saveRecoveryCodes(array $codes, AuthenticatorData $authenticatorData)
    {
        $authenticatorData->setRecoveryCodes($codes);
        $authenticatorData->setLastRecoveryTime(time());
        $this->plugin->saveData($authenticatorData->getUserId(), $authenticatorData);
    }

    protected function initialize()
    {
        $this->extensionChecker = $this->dic->get(PhpExtensionChecker::class);
        $this->plugin = $this->dic->get(PluginManager::class)
            ->getPlugin(Plugin::PLUGIN_NAME);
    }
}